/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/ssl.h>
#include <common/c++/lock.h>
#include <common/lazy.h>
#include <common/misc.h>
#include <common/size.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <limits.h>
#include <string.h>

#include <vector>

namespace {

#ifndef SSL_MODE_ASYNC
#define SSL_MODE_ASYNC    0
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L && \
   (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2090300fL)
#define TLS_client_method SSLv23_client_method
#define TLS_server_method SSLv23_server_method
#endif

void
error_set_openssl(error *err, int code)
{
   error_clear(err);
   memcpy(&err->source, "ossl", MIN(sizeof(err->source), 4));
   err->code = code;
   err->get_string = [] (error *err) -> const char *
   {
      if (!err->context)
      {
         char buf[256]; // documented size in ERR_error_string manpage.
         if (ERR_error_string(err->code, buf))
         {
            err->context = strdup(buf);
            if (err->context)
               err->free_fn = [] (void *p) -> void { free(p); };
         }
      }
      return (const char*)err->context;
   };
}

void
error_set_openssl_verify(error *err, long code)
{
   error_clear(err);
   memcpy(&err->source, "x509", MIN(sizeof(err->source), 4));
   err->code = code;
   err->get_string = [] (error *err) -> const char *
   {
      return X509_verify_cert_error_string(err->code);
   };
}

void
init_library(error *err)
{
   // SSL_library_init is required below version 1.1.0.
   // Version 1.1.0 introduces OPENSSL_init_ssl() but documents that it is
   // not required.
   //
#if OPENSSL_VERSION_NUMBER < 0x10100000L
   static lazy_init_state st = {0};

   lazy_init(
      &st,
      [] (void *context, error *err) -> void
      {
         SSL_library_init();
         SSL_load_error_strings();
         OPENSSL_config(nullptr);
      },
      nullptr,
      err
   );
#endif
}

#if (OPENSSL_VERSION_NUMBER < 0x10101000L) || defined(LIBRESSL_VERSION_NUMBER)
#define NEED_EX_IO

int
SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);

int
SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *read);

int
BIO_write_ex(BIO *bio, const void *buf, size_t num, size_t *written);

int
BIO_read_ex(BIO *bio, void *buf, size_t num, size_t *read);
#endif

struct OpenSslFilter : public pollster::Filter
{
   SSL *ssl;
   SSL_CTX *ctx;
   BIO *contextBio, *networkBio;
   std::mutex writeLock;
   std::vector<char> pendingWrites;
   struct PendingWriteCallback
   {
      size_t off;
      std::function<void(error*)> fn;
   };
   std::vector<PendingWriteCallback> plaintextWriteCallbacks;
   std::vector<PendingWriteCallback> ciphertextWriteCallbacks;
   std::vector<char> pendingRead;
   bool initialHandshake;
   bool hostnameSet;
   pollster::SslArgs::CallbackStruct cb;

   OpenSslFilter()
      : ssl(nullptr),
        ctx(nullptr),
        contextBio(nullptr),
        networkBio(nullptr),
        initialHandshake(false),
        hostnameSet(false)
   {
   }

   ~OpenSslFilter()
   {
      if (ssl)
      {
         SSL_free(ssl);
         ssl = nullptr;

         // Owned by the context.
         //
         contextBio = nullptr;
      }

      if (ctx)
      {
         SSL_CTX_free(ctx);
         ctx = nullptr;
      }

      for (auto &bio : { contextBio, networkBio })
      {
         if (bio)
         {
            BIO_free(bio);
         }
      }
   }

   void
   Initialize(pollster::SslArgs &args, error *err)
   {
      init_library(err);
      ERROR_CHECK(err);

      cb = std::move(args.Callbacks);

      if (!(ctx = SSL_CTX_new(args.ServerMode ? TLS_server_method() : TLS_client_method())))
         ERROR_SET(err, unknown, "Failed to create SSL context");

      if (!(ssl = SSL_new(ctx)))
         ERROR_SET(err, unknown, "Failed to create SSL object");

      if (args.HostName)
      {
         if (!SSL_set_tlsext_host_name(ssl, args.HostName))
            ERROR_SET(err, unknown, "Failed to set hostname");

         auto param = SSL_get0_param(ssl);

         X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

         if (!X509_VERIFY_PARAM_set1_host(param, args.HostName, strlen(args.HostName)))
            ERROR_SET(err, unknown, "Failed to set hostname");

         if (!SSL_CTX_set_default_verify_paths(ctx))
            ERROR_SET(err, unknown, "Failed to load default CA");

         SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

         hostnameSet = true;
      }

      if (!BIO_new_bio_pair(&contextBio, 0, &networkBio, 0))
         ERROR_SET(err, unknown, "Failed to create bio pair");

      SSL_set_bio(ssl, contextBio, contextBio);

      SSL_set_mode(
         ssl,
         SSL_MODE_ENABLE_PARTIAL_WRITE |
            SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
            SSL_MODE_ASYNC |
            SSL_MODE_AUTO_RETRY
      );

      if (args.ServerMode)
         SSL_set_accept_state(ssl);
      else
         SSL_set_connect_state(ssl);
   exit:;
   }

   void
   AddPendingCallback(size_t len, std::vector<PendingWriteCallback> &cbList, const std::function<void(error*)> &onComplete, error *err)
   {
      try
      {
         PendingWriteCallback cb;

         cb.off = len;
         cb.fn = onComplete;

         for (const auto &p : cbList)
            cb.off -= p.off;

         cbList.push_back(std::move(cb));
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   }

   template<typename IoFn, typename InvokeFn>
   void
   PerformIoWithCallbacks(size_t currentLen, std::vector<PendingWriteCallback> &cbList, IoFn io, InvokeFn invoke, error *err)
   {
      size_t len = 0;
      size_t out = 0;
      std::function<void(error*)> blankFn;

   retry:
      // Remove last interation's bytes from consideration.
      //
      currentLen -= out;

      if (!currentLen)
         return;

      // If there is a callback for a range of bytes, perform I/O on that size.
      // Otherwise try the whole buffer.
      //
      len = cbList.size() ? MIN(currentLen, cbList[0].off) : currentLen;
      out = 0;
      io(
         len,
         &out,
         (cbList.size() && len == cbList[0].off) ? cbList[0].fn : blankFn,
         err
      );
      ERROR_CHECK(err);
      if (!out)
         goto exit;

      if (cbList.size())
      {
         auto &cb = cbList[0];
         bool largerBuffer = currentLen < cb.off;

         cb.off -= out;
         if (!cb.off)
         {
            // Call callback and remove from list.
            //
            invoke(cb.fn, err);
            ERROR_CHECK(err);
            cbList.erase(cbList.begin());
            goto retry;
         }

         // Buffer was smaller than cb.off?
         // Retry.
         //
         if (len == out && largerBuffer)
            goto retry;
      }
      if (len != out)
         goto retry;
   exit:;
   }

   void
   AppendWriteToBuffer(const void *buf, int len, const std::function<void(error*)> &onComplete, error *err)
   {
      try
      {
         pendingWrites.insert(pendingWrites.end(), (const char*)buf, (const char*)buf+len);
         if (onComplete)
         {
            AddPendingCallback(len, plaintextWriteCallbacks, onComplete, err);
            ERROR_CHECK(err);
         }
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   }

   void
   Write(const void *buf, int len, const std::function<void(error*)> &onComplete)
   {
      error err;

      common::locker l;

      l.acquire(writeLock);

      if (!initialHandshake || pendingWrites.size())
      {
         AppendWriteToBuffer(buf, len, onComplete, &err);
         ERROR_CHECK(&err);

         if (!initialHandshake)
         {
            TryHandshakeUnlocked(&err);
            ERROR_CHECK(&err);

            if (!initialHandshake)
               goto exit;
         }
      }
      else
      {
         size_t out = 0;
         int r = 0;
      retry:
         r = SSL_write_ex(ssl, buf, len, &out);
         if (r == 1)
         {
            if (len == out)
            {
               if (onComplete)
               {
                  size_t pending = BIO_ctrl_pending(networkBio);
                  AddPendingCallback(pending, ciphertextWriteCallbacks, onComplete, &err);
                  ERROR_CHECK(&err);
               }
            }
            else
            {
               AppendWriteToBuffer((const char*)buf + out, len - out, onComplete, &err);
               ERROR_CHECK(&err);
               goto exit;
            }
         }
         else
         {
            int code = SSL_get_error(ssl, r);
            switch (code)
            {
            case SSL_ERROR_WANT_WRITE:
               if (TryCiphertextWriteUnlocked(&err))
                  goto retry;
               ERROR_CHECK(&err);
               // fall through
            case SSL_ERROR_WANT_READ:
               AppendWriteToBuffer(buf, len, onComplete, &err);
               ERROR_CHECK(&err);
               goto exit;
            default:
               ERROR_SET(&err, unknown, "SSL error");
            }
         }
      }
      TryPendingWritesUnlocked(&err);
      ERROR_CHECK(&err);
   exit:
      if (ERROR_FAILED(&err) && Events.get())
      {
         Events->OnAsyncError(&err);
      }
   }

   void
   TryPendingWritesUnlocked(error *err)
   {
      PerformIoWithCallbacks(
         pendingWrites.size(),
         plaintextWriteCallbacks,
         [&] (size_t len, size_t *out, const std::function<void(error*)> &onComplete, error *err) -> void
         {
            int r = 0;
         retry:
            r = SSL_write_ex(ssl, pendingWrites.data(), len, out);
            if (r == 1)
            {
               pendingWrites.erase(pendingWrites.begin(), pendingWrites.begin()+*out);
            }
            else
            {
               int code = SSL_get_error(ssl, r);
               switch (code)
               {
               case SSL_ERROR_WANT_WRITE:
                  if (TryCiphertextWriteUnlocked(err))
                     goto retry;
                  ERROR_CHECK(err);
                  // fall through
               case SSL_ERROR_WANT_READ:
                  break;
               default:
                  ERROR_SET(err, openssl, code);
               }
            }
         exit:;
         },
         [&] (const std::function<void(error*)> &fn, error *err) -> void
         {
            size_t pending = BIO_ctrl_pending(networkBio);
            AddPendingCallback(pending, ciphertextWriteCallbacks, fn, err);
         },
         err
      );
      ERROR_CHECK(err);

      TryCiphertextWriteUnlocked(err);
      ERROR_CHECK(err);
   exit:;
   }

   void
   TryPendingWrites(error *err)
   {
      if (initialHandshake)
      {
         common::locker l;

         l.acquire(writeLock);
         TryPendingWritesUnlocked(err);
         ERROR_CHECK(err);
      }
   exit:;
   }

   bool
   TryCiphertextWrite(error *err)
   {
      if (!BIO_ctrl_pending(networkBio))
         return false;

      common::locker l;
      l.acquire(writeLock);
      return TryCiphertextWriteUnlocked(err);
   }

   bool
   TryCiphertextWriteUnlocked(error *err)
   {
      size_t pending = 0;
      const int bufsz = 4096;
      bool found = false;

      while ((pending = MIN(bufsz, BIO_ctrl_pending(networkBio))))
      {
         PerformIoWithCallbacks(
            pending,
            ciphertextWriteCallbacks,
            [&] (size_t len, size_t *out, std::function<void(error*)> &onComplete, error *err) -> void
            {
               char buf[bufsz];
               int r = BIO_read_ex(networkBio, buf, len, out);
               if (r == 1)
               {
                  if (Events.get())
                  {
                     std::function<void(error*)> cb;

                     if (onComplete && len == *out)
                     {
                        cb = std::move(onComplete);
                        onComplete = [] (error *err) -> void {};
                     }

                     Events->OnBytesToWrite(buf, *out, cb);
                  }
                  found = true;
               }
               else if (!BIO_should_retry(networkBio))
               {
                  ERROR_SET(err, unknown, "BIO_read_ex failed");
               }
            exit:;
            },
            [] (const std::function<void(error*)> &fn, error *err) -> void
            {
               if (fn)
                  fn(err);
            },
            err
         );
         ERROR_CHECK(err);
      }
   exit:
      return found;
   }

   void
   InsertPendingRead(const void *buf, size_t len, error *err)
   {
      if (!len)
         goto exit;
      try
      {
         pendingRead.insert(pendingRead.begin(), (const char*)buf, (const char*)buf+len);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   }

   void
   OnBytesReceived(const void *buf, int len, error *err)
   {
      size_t out = 0;
      int r = 0;
      bool heap = false;
      size_t slen = len;

      if (pendingRead.size())
      {
         InsertPendingRead(buf, len, err);
         ERROR_CHECK(err);

         heap = true;
         buf = pendingRead.data();
         slen = pendingRead.size();
      }

      for (;;)
      {
         bool found = false;

         if (slen)
         {
            r = BIO_write_ex(networkBio, buf, slen, &out);
            if (r == 1)
            {
               buf = (const char*)buf + out;
               slen -= out;
            }
            else if (!BIO_should_retry(networkBio))
               ERROR_SET(err, unknown, "BIO_write_ex error");
         }

         if (!initialHandshake)
         {
            TryHandshake(err);
            ERROR_CHECK(err);
         }

         if (initialHandshake)
         {
            TryPendingWrites(err);
            ERROR_CHECK(err);

            if (TryPlaintextRead(err))
               found = true;
            ERROR_CHECK(err);

            if (TryCiphertextWrite(err))
               found = true;
            ERROR_CHECK(err);
         }

         if (!found)
            break;
      }

      if (heap)
         pendingRead.erase(pendingRead.begin(), pendingRead.begin() + pendingRead.size() - slen);
      else if (slen)
      {
         InsertPendingRead(buf, slen, err);
         ERROR_CHECK(err);
      }
   exit:;
   }

   bool
   TryPlaintextRead(error *err)
   {
      bool found = false;

      if (!initialHandshake)
         return found;

      char buf[4096];
      size_t out = 0;
   retry:
      int r = SSL_read_ex(ssl, buf, sizeof(buf), &out);
      if (r == 1)
      {
         found = true;
         if (Events.get())
         {
            Events->OnBytesReceived(buf, out, err);
            ERROR_CHECK(err);
         }
         goto retry;
      }
      else
      {
         int code = SSL_get_error(ssl, r);
         switch (code)
         {
         case SSL_ERROR_WANT_WRITE:
         case SSL_ERROR_WANT_READ:
         // Seems to be an issue with older OpenSSL or libressl,
         // perhaps specific to the way we're using BIO.
         // Newer OpenSSL doesn't need it.
         //
         case SSL_ERROR_SYSCALL:
            break;
         case SSL_ERROR_ZERO_RETURN:
            if (Events.get())
            {
               Events->OnClosed(err);
               ERROR_CHECK(err);
            }
            break;
         default:
            ERROR_SET(err, openssl, code);
         }
      }
   exit:
      return found;
   }

   void
   TryHandshake(error *err)
   {
      if (initialHandshake)
         return;

      common::locker l;
      l.acquire(writeLock);
      TryHandshakeUnlocked(err);
   }

   void
   TryHandshakeUnlocked(error *err)
   {
      if (!initialHandshake)
      {
         int r = 0;
      retry:
         r = SSL_do_handshake(ssl);
         if (r == 1)
         {
            if (hostnameSet)
            {
               auto cert = SSL_get_peer_certificate(ssl);
               if (!cert)
                  ERROR_SET(err, unknown, "Could not get certificate");

               long verify = SSL_get_verify_result(ssl);

               if (verify != X509_V_OK)
               {
                  ERROR_SET(err, openssl_verify, verify);
               }
            }

            if (cb.OnCipherKnown)
            {
               auto cipher = SSL_get_current_cipher(ssl);
               if (cipher)
               {
                  auto name = SSL_CIPHER_get_name(cipher);
                  if (name)
                  {
                     cb.OnCipherKnown(name, err);
                     ERROR_CHECK(err);
                  }
               }
            }

            // TODO: additional validation on cert chain?

            initialHandshake = true;

            TryPendingWritesUnlocked(err);
            ERROR_CHECK(err);
         }
         else
         {
            int code = SSL_get_error(ssl, r);
            switch (code)
            {
            case SSL_ERROR_WANT_READ:
               if (TryCiphertextWriteUnlocked(err))
                  goto retry;
               ERROR_CHECK(err);
               // fall through
            case SSL_ERROR_WANT_WRITE:
               break;
            default:
               ERROR_SET(err, openssl, code);
            }
         }
      }
   exit:;
   }

   bool
   TryPendingReads(error *err)
   {
      if (pendingRead.size())
      {
         OnBytesReceived(nullptr, 0, err);
         ERROR_CHECK(err);
         return true;
      }
   exit:
      return false;
   }

   void
   OnEof()
   {
      error err;

      TryPendingReads(&err);
      if (!ERROR_FAILED(&err))
         TryPlaintextRead(&err);
   }

   void
   OnEventsInitialized(error *err)
   {
      TryHandshake(err);
   }
};

} // end namespace

void
pollster::CreateSslFilter(
   SslArgs &args,
   std::shared_ptr<pollster::Filter> &res,
   error *err
)
{
   OpenSslFilter *f = nullptr;
   try
   {
      f = new OpenSslFilter();
      res = std::shared_ptr<pollster::Filter>(f);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   f->Initialize(args, err);
   ERROR_CHECK(err);

exit:
   if (ERROR_FAILED(err))
   {
      if (f && f != res.get())
         delete f;
      res = nullptr;
   }
}

#ifdef NEED_EX_IO
namespace {

template<typename InnerFn, typename T>
int
readwrite_ex(T *buf, size_t num, size_t *out, InnerFn fn)
{
   int r = 0;

   *out = 0;

   error err;
   common::IntIoFuncToSizeT(
      [&] (int n, error *err) -> int
      {
         return fn(buf, n);
      },
      [&] (int n) -> void
      {
         *out += n;
         buf = (char*)buf + n;
         num -= n;
      },
      num,
      &err
   );
   ERROR_CHECK(&err);

exit:
   if (*out)
      r = 1;
   return r;
}

int
SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
{
   return readwrite_ex(
      buf, num, written,
      [ssl] (const void *buf, int num) -> int
      {
         return SSL_write(ssl, buf, num);
      }
   );
}

int
SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *read)
{
   return readwrite_ex(
      buf, num, read,
      [ssl] (void *buf, int num) -> int
      {
         return SSL_read(ssl, buf, num);
      }
   );
}

int
BIO_write_ex(BIO *bio, const void *buf, size_t num, size_t *written)
{
   return readwrite_ex(
      buf, num, written,
      [bio] (const void *buf, int num) -> int
      {
         return BIO_write(bio, buf, num);
      }
   );
}

int
BIO_read_ex(BIO *bio, void *buf, size_t num, size_t *read)
{
   return readwrite_ex(
      buf, num, read,
      [bio] (void *buf, int num) -> int
      {
         return BIO_read(bio, buf, num);
      }
   );
}

} // end namespace
#endif