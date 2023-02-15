/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/ssl.h>
#include <common/c++/lock.h>
#include <common/c++/new.h>
#include <common/lazy.h>
#include <common/misc.h>
#include <common/size.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <limits.h>
#include <string.h>

#include <vector>

namespace {

X509_STORE *x509_store = nullptr;

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

   if (code == SSL_ERROR_SSL)
   {
      char buf[4096];
      struct remaining
      {
         char *p;
         size_t n;
      };
      remaining space = {buf, sizeof(buf)-1};
      ERR_print_errors_cb(
         [] (const char *str, size_t n, void *ctx) -> int
         {
            auto space = (remaining*)ctx;
            auto m = MIN(space->n, n);
            memcpy(space->p, str, m+1);
            space->p += m;
            space->n -= m;
            return !space->n;
         },
         &space
      );
      err->context = strdup(buf);
      if (err->context)
         err->free_fn = [] (void *p) -> void { free(p); };
   };

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
SetCertificate(SSL *ctx, pollster::Certificate *cert, error *err);

void
init_library(error *err)
{
   static lazy_init_state st = {0};

   lazy_init(
      &st,
      [] (void *context, error *err) -> void
      {
         // SSL_library_init is required below version 1.1.0.
         // Version 1.1.0 introduces OPENSSL_init_ssl() but documents that it is
         // not required.
         //
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
         SSL_library_init();
         SSL_load_error_strings();
         OPENSSL_config(nullptr);
         OpenSSL_add_all_algorithms();
#else
         OPENSSL_init_ssl(
            OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
            nullptr
         );
         OPENSSL_init_crypto(
            OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG,
            nullptr
         );
#endif

         // Initialize the cert store early.  This lets us do things like run
         // SSL clients in a chroot, so long as we hit this code first.
         //
         auto store = X509_STORE_new();
         if (!store)
            ERROR_SET(err, nomem);

         if (!X509_STORE_set_default_paths(store))
            ERROR_SET(err, unknown, "Error loading x509 store");

         x509_store = store;
         store = nullptr;

      exit:
         if (store)
            X509_STORE_free(store);
      },
      nullptr,
      err
   );
}

#if (OPENSSL_VERSION_NUMBER < 0x10101000L) || defined(LIBRESSL_VERSION_NUMBER)

#define NEED_EX_IO
#if !defined(LIBRESSL_VERSION_NUMBER) || (LIBRESSL_VERSION_NUMBER < 0x3050100fL)
#define NEED_SSL_EX_IO
#endif

#ifdef NEED_SSL_EX_IO
int
SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);

int
SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *read);
#endif

int
BIO_write_ex(BIO *bio, const void *buf, size_t num, size_t *written);

int
BIO_read_ex(BIO *bio, void *buf, size_t num, size_t *read);

void
SSL_CTX_set1_cert_store(SSL_CTX *ctx, X509_STORE *store)
{
   SSL_CTX_set_cert_store(ctx, store);
   if (store)
      X509_STORE_up_ref(store);
}

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
   bool pendingShutdown;
   pollster::SslArgs::CallbackStruct cb;

   OpenSslFilter()
      : ssl(nullptr),
        ctx(nullptr),
        contextBio(nullptr),
        networkBio(nullptr),
        initialHandshake(false),
        hostnameSet(false),
        pendingShutdown(false)
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

      if (!BIO_new_bio_pair(&contextBio, 0, &networkBio, 0))
         ERROR_SET(err, unknown, "Failed to create bio pair");

      SSL_set_bio(ssl, contextBio, contextBio);

      if (args.ServerMode)
         SSL_set_accept_state(ssl);
      else
         SSL_set_connect_state(ssl);

      SSL_set_mode(
         ssl,
         SSL_MODE_ENABLE_PARTIAL_WRITE |
            SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
            SSL_MODE_ASYNC |
            SSL_MODE_AUTO_RETRY
      );

      SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_COMPRESSION);
      SSL_CTX_set_ecdh_auto(ctx, 1);

      SSL_CTX_set1_cert_store(ctx, x509_store);

      if (args.HostName)
      {
         if (!SSL_set_tlsext_host_name(ssl, args.HostName))
            ERROR_SET(err, unknown, "Failed to set hostname");

         auto param = SSL_get0_param(ssl);

         X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

         if (!X509_VERIFY_PARAM_set1_host(param, args.HostName, strlen(args.HostName)))
            ERROR_SET(err, unknown, "Failed to set hostname");

         SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

         hostnameSet = true;
      }

      if (args.Certificate.Get())
      {
         SetCertificate(ssl, args.Certificate.Get(), err);
         ERROR_CHECK(err);
      }
   exit:;
   }

   void
   AddPendingCallback(size_t len, std::vector<PendingWriteCallback> &cbList, const std::function<void(error*)> &onComplete, error *err)
   {
      if (cbList.size() && (len == 0 || cbList[cbList.size()-1].off == 0))
      {
         auto &cb = cbList[cbList.size() - 1];
         auto oldFn = std::move(cb.fn);
         cb.off += len;
         cb.fn = [oldFn, onComplete] (error *err) -> void
         {
            oldFn(err);
            onComplete(err);
         };
         return;
      }

      try
      {
         PendingWriteCallback cb;

         cb.off = len;
         cb.fn = onComplete;

         for (const auto &p : cbList)
            cb.off -= p.off;

         cbList.push_back(std::move(cb));
      }
      catch (const std::bad_alloc&)
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
   AppendWriteToBuffer(const void *buf, size_t len, const std::function<void(error*)> &onComplete, error *err)
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
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   }

   void
   Write(const void *buf, size_t len, const std::function<void(error*)> &onComplete)
   {
      error err;

      common::locker l;

      if (!len && !onComplete)
         return;

      l.acquire(writeLock);

      if (!initialHandshake || pendingWrites.size())
      {
         AppendWriteToBuffer(buf, len, onComplete, &err);
         ERROR_CHECK(&err);

         if (!initialHandshake)
         {
            if (SSL_is_server(ssl))
               goto exit;

            TryHandshakeUnlocked(&err);
            ERROR_CHECK(&err);

            if (!initialHandshake)
               goto exit;
         }
      }
      else if (!len && onComplete)
      {
         // empty write.
         // pendingWrites.size() is zero, so we can set up the i/o callback now.
         //
         l.release();

         if (Events.get())
            Events->OnBytesToWrite(nullptr, 0, onComplete);
         goto exit;
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
      bool hadWrite = pendingWrites.size();

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

      if (pendingShutdown && (!hadWrite || (hadWrite && !pendingWrites.size())))
      {
         TryPendingShutdownUnlocked(err);
      }

      TryCiphertextWriteUnlocked(err);
      ERROR_CHECK(err);
   exit:;
   }

   void CloseNotify(error *err)
   {
      common::locker l;

      l.acquire(writeLock);

      pendingShutdown = true;

      if (!pendingWrites.size())
      {
         TryPendingShutdownUnlocked(err);
         ERROR_CHECK(err);
         TryCiphertextWriteUnlocked(err);
         ERROR_CHECK(err);
      }
   exit:;
   }

   void
   TryPendingShutdownUnlocked(error *err)
   {
      int r = 0;
      bool retried = false;
   retry:
      r = SSL_shutdown(ssl);
      if (r == 0)
      {
         int code = SSL_get_error(ssl, r);
         switch (code)
         {
         case SSL_ERROR_SYSCALL:
            if (retried)
               break;
            retried = true;
            // fall through
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
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   }

   void
   OnBytesReceived(const void *buf, size_t len, error *err)
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
            case SSL_ERROR_SYSCALL:
               break;
            default:
               if (TryCiphertextWriteUnlocked(err))
                  break;
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
      if (!SSL_is_server(ssl))
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
   catch (const std::bad_alloc&)
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

#ifdef NEED_SSL_EX_IO

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

#endif

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

void
pollster::InitSslLibrary(error *err)
{
   init_library(err);
}

static
void
ReadIntoBio(common::Stream *stream, BIO *bio, error *err)
{
   char buf[4096];

   for (;;)
   {
      auto r = stream->Read(buf, sizeof(buf), err);
      ERROR_CHECK(err);
      if (r <= 0)
         break;

      auto p = buf;
   retry:
      size_t out = 0;
      int r2 = BIO_write_ex(bio, p, r, &out);
      if (r2 == 1)
      {
         p += out;
         r -= out;
         if (r)
            goto retry;
      }
      else if (!BIO_should_retry(bio))
         ERROR_SET(err, unknown, "BIO_write_ex error");
   }
exit:;
}

namespace {

struct OpenSslCert : public pollster::Certificate
{
   X509 *cert;
   std::vector<X509*> intermediaries;
   EVP_PKEY *key;

   OpenSslCert() : cert(nullptr), key(nullptr) {}
   ~OpenSslCert()
   {
      if (cert)
         X509_free(cert);
      for (auto i : intermediaries)
         X509_free(i);
      if (key)
         EVP_PKEY_free(key);
   }

   void *
   GetNativeObject() { return cert; }
};

void
SetCertificate(SSL *ssl, pollster::Certificate *genericCert, error *err)
{
   auto cert = (OpenSslCert *)genericCert;

   if (!SSL_use_certificate(ssl, cert->cert))
      ERROR_SET(err, unknown, "Failed to set certificate");

   SSL_clear_chain_certs(ssl);

   for (auto intermediary : cert->intermediaries)
   {
      if (!SSL_add1_chain_cert(ssl, intermediary))
         ERROR_SET(err, unknown, "Failed to add to cert chain");
   }

   if (!SSL_use_PrivateKey(ssl, cert->key))
      ERROR_SET(err, unknown, "Failed to set private key");

   if (!SSL_check_private_key(ssl))
      ERROR_SET(err, unknown, "Private key check failed");
exit:;
}

} // end namepsace

void
pollster::CreateCertificate(
   common::Stream *stream,
   Certificate **output,
   error *err
)
{
   common::Pointer<OpenSslCert> r;
   BIO *bio = nullptr;
   X509 *intermediary = nullptr;
   int64_t oldPos = 0;

   auto initBio = [&] () -> void
   {
      if (bio)
         BIO_free(bio);

      bio = BIO_new(BIO_s_mem());
      if (!bio)
         ERROR_SET(err, nomem);

      ReadIntoBio(stream, bio, err);
      ERROR_CHECK(err);

      BIO_set_mem_eof_return(bio, 0);
   exit:;
   };

   init_library(err);
   ERROR_CHECK(err);

   oldPos = stream->GetPosition(err);
   ERROR_CHECK(err);

   initBio();
   ERROR_CHECK(err);

   common::New(r, err);
   ERROR_CHECK(err);

   r->cert = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr);
   if (!r->cert)
      ERROR_SET(err, unknown, "Failed to load cert");

   while ((intermediary = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)))
   {
      try
      {
         r->intermediaries.push_back(intermediary);
      }
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }
   }

   ERR_clear_error();

   // Need to rewind the stream to read private key...
   //
   stream->Seek(oldPos, SEEK_SET, err);
   ERROR_CHECK(err);
   initBio();
   ERROR_CHECK(err);

   r->key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
   if (!r->key)
      ERROR_SET(err, unknown, "Failed to read private key");

   if (!X509_check_private_key(r->cert, r->key))
      ERROR_SET(err, unknown, "Cert does not match key");

exit:
   if (ERROR_FAILED(err))
      r = nullptr;
   if (bio)
      BIO_free(bio);
   if (intermediary)
      X509_free(intermediary);
   *output = r.Detach();
}
