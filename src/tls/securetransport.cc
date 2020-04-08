/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// This is the deprecated interface on Darwin.  The replacement interface
// does not support buffer-oriented operation and insists that it speak
// TCP for you.  So this, or OpenSSL, is the best we can do on Darwin.
//

#include <pollster/ssl.h>

#include <common/c++/lock.h>
#include <common/misc.h>

#include <string.h>
#include <utility>
#include <vector>

#include <Security/SecureTransport.h>

namespace {

const char *
GetCipherSuiteName(SSLCipherSuite suite);

struct SecureTransportFilter : public pollster::Filter
{
   SSLContextRef ssl;
   SSLProtocolSide side;
   pollster::SslArgs::CallbackStruct cb;
   std::vector<char> bufferedReads;
   const void *currentReadBuf;
   size_t currentReadBufLen;
   std::mutex writeLock;
   bool handshakeComplete;
   std::vector<std::pair<std::vector<char>, std::function<void(error*)>>> pendingWrites;

   struct WriteCallback : public std::enable_shared_from_this<WriteCallback>
   {
      std::function<void(error *err)> InnerCallback;
      std::mutex lock;
      int Count;

      WriteCallback() : Count(0) {}

      std::function<void(error *err)>
      Wrap()
      {
          ++Count;
          auto p = shared_from_this();
          return [p] (error *err) -> void { p->Call(err); };
      }

      void
      Call(error *err)
      {
         common::locker l;
         l.acquire(lock);
         if (!--Count)
            InnerCallback(err);
      }
   };
   std::shared_ptr<WriteCallback> currentWriteCb;

   SecureTransportFilter() :
     ssl(nullptr),
     side(kSSLClientSide),
     currentReadBuf(nullptr),
     currentReadBufLen(0),
     handshakeComplete(false)
   {
   }

   ~SecureTransportFilter()
   {
      if (ssl)
         CFRelease(ssl);
   }

   void
   Initialize(pollster::SslArgs &args, error *err)
   {
      OSStatus status = 0;

      cb = args.Callbacks;
      side = args.ServerMode ? kSSLServerSide : kSSLClientSide;

      ssl = SSLCreateContext(nullptr, side, kSSLStreamType);
      if (!ssl)
         ERROR_SET(err, unknown, "Couldn't create SSL context");

      SSLSetConnection(ssl, this);
      SSLSetIOFuncs(
         ssl,
         // read
         [] (SSLConnectionRef connection, void *data, size_t *len) -> OSStatus
         {
            auto This = (SecureTransportFilter*)connection;
            size_t lenIn = *len;
            size_t lenOut = 0;
            size_t n = 0;

            auto &bufferedReads = This->bufferedReads;
            auto &currentReadBuf = This->currentReadBuf;
            auto &currentReadBufLen = This->currentReadBufLen;

            n = MIN(lenIn, bufferedReads.size());
            if (n)
            {
               memcpy(data, bufferedReads.data(), n);
               data = (char*)data+n;
               lenIn -= n;
               lenOut += n;
               bufferedReads.erase(bufferedReads.begin(), bufferedReads.begin()+n);
            }

            n = MIN(lenIn, currentReadBufLen);
            if (n)
            {
               memcpy(data, currentReadBuf, n);
               data = (char*)data+n;
               currentReadBuf = (const char*)currentReadBuf + n;
               lenIn -= n;
               currentReadBufLen -= n;
               lenOut += n;
            }

            *len = lenOut;
            if (lenIn)
               return errSSLWouldBlock;
            return 0;
         },
         // write
         [] (SSLConnectionRef connection, const void *data, size_t *len) -> OSStatus
         {
            auto This = (SecureTransportFilter*)connection;
            if (This->Events.get())
            {
               auto &currentWriteCb = This->currentWriteCb;
               This->Events->OnBytesToWrite(data, *len, currentWriteCb.get() ? currentWriteCb->Wrap(): std::function<void(error*)>());
               return 0;
            }
            *len = 0;
            return errSSLWouldBlock;
         }
      );

      if (args.HostName)
      {
         status = SSLSetPeerDomainName(ssl, args.HostName, strlen(args.HostName));
         if (status)
            ERROR_SET(err, osstatus, status);
      }

   exit:;
   }

   void
   TryHandshake(error *err)
   {
      OSStatus status = 0;
      common::locker l;

      status = SSLHandshake(ssl);
      switch (status)
      {
      case 0:
         if (cb.OnCipherKnown)
         {
            SSLCipherSuite suite = 0;
            status = SSLGetNegotiatedCipher(ssl, &suite);
            if (status)
               ERROR_SET(err, osstatus, status);
            const char *name = GetCipherSuiteName(suite);
            if (!name)
               name = "Unrecognized";
            cb.OnCipherKnown(name, err);
            ERROR_CHECK(err);
         }
         ERROR_CHECK(err);
         l.acquire(writeLock);
         handshakeComplete = true;
         for (auto &p : pendingWrites)
            Write(p.first.data(), p.first.size(), p.second, false);
         pendingWrites.resize(0);
         pendingWrites.shrink_to_fit();
         l.release();
         break;
      case errSSLWouldBlock:
         break;
      default:
         ERROR_SET(err, osstatus, status);
      }
   exit:;
   }

   void
   Write(const void *buf, size_t len, const std::function<void(error*)> &onComplete)
   {
      Write(buf, len, onComplete, true);
   }

   void
   Write(const void *buf, size_t len, const std::function<void(error*)> &onComplete, bool locked)
   {
      std::shared_ptr<WriteCallback> writeCb;
      std::function<void(error*)> wrappedCb;
      common::locker l;
      error err;

      if (onComplete)
      {
         try
         {
            writeCb = std::make_shared<WriteCallback>();
            writeCb->InnerCallback = onComplete;
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(&err, nomem);
         }
      }

      if (locked)
         l.acquire(writeLock);

      if (!handshakeComplete)
      {
         try
         {
            std::vector<char> tmp;
            tmp.insert(tmp.end(), (const char*)buf, (const char*)buf+len);
            pendingWrites.push_back(std::make_pair(std::move(tmp), onComplete));
            goto exit;
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(&err, nomem);
         }
      }

      currentWriteCb = writeCb;
      if (writeCb.get())
         wrappedCb = writeCb->Wrap();

      do
      {
         size_t out = 0;
         OSStatus status = SSLWrite(ssl, buf, len, &out);
         if (status)
            ERROR_SET(&err, osstatus, status);
         buf = (const char*)buf+out;
         len -= out;
      } while (len);

      currentWriteCb = std::shared_ptr<WriteCallback>();
      if (wrappedCb)
      {
         wrappedCb(&err);
         ERROR_CHECK(&err);
      }

   exit:
      if (ERROR_FAILED(&err) && Events.get())
      {
         Events->OnAsyncError(&err);
      }
   }

   void
   TryPlaintextRead(error *err)
   {
      char buf[4096];
      OSStatus status = 0;
      size_t out = 0;

      while (!(status = SSLRead(ssl, buf, sizeof(buf), &out)) && out)
      {
         Events->OnBytesReceived(buf, out, err);
         ERROR_CHECK(err);
         out = 0;
      }

      switch(status)
      {
      case 0:
      case errSSLWouldBlock:
         break;
      case errSSLClosedGraceful:
         if (Events.get())
         {
            Events->OnClosed(err);
            ERROR_CHECK(err);
         }
         break;
      default:
         ERROR_SET(err, osstatus, status);
      }

   exit:;
   }

   void
   OnBytesReceived(const void *buf, size_t len, error *err)
   {
      currentReadBuf = buf;
      currentReadBufLen = len;

      if (!handshakeComplete)
      {
         TryHandshake(err);
         ERROR_CHECK(err);
      }
      if (handshakeComplete)
      {
         TryPlaintextRead(err);
         ERROR_CHECK(err);
      }

      if (currentReadBufLen)
      {
         try
         {
            bufferedReads.insert(bufferedReads.end(), (char*)currentReadBuf, (char*)currentReadBuf+currentReadBufLen);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      }
   exit:
      currentReadBuf = nullptr;
      currentReadBufLen = 0;
   }

   void
   OnEventsInitialized(error *err)
   {
      if (side == kSSLClientSide)
      {
         TryHandshake(err);
      }
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
   SecureTransportFilter *f = nullptr;
   try
   {
      f = new SecureTransportFilter();
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

namespace {
const char *
GetCipherSuiteName(SSLCipherSuite suite)
{
   switch (suite)
   {
#define MAP(X) case X: return #X;
   MAP(SSL_RSA_EXPORT_WITH_RC4_40_MD5);
   MAP(SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
   MAP(SSL_RSA_WITH_IDEA_CBC_SHA);
   MAP(SSL_RSA_EXPORT_WITH_DES40_CBC_SHA);
   MAP(SSL_RSA_WITH_DES_CBC_SHA);
   MAP(SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
   MAP(SSL_DH_DSS_WITH_DES_CBC_SHA);
   MAP(SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
   MAP(SSL_DH_RSA_WITH_DES_CBC_SHA);
   MAP(SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
   MAP(SSL_DHE_DSS_WITH_DES_CBC_SHA);
   MAP(SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
   MAP(SSL_DHE_RSA_WITH_DES_CBC_SHA);
   MAP(SSL_DH_anon_EXPORT_WITH_RC4_40_MD5);
   MAP(SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
   MAP(SSL_DH_anon_WITH_DES_CBC_SHA);
   MAP(SSL_FORTEZZA_DMS_WITH_NULL_SHA);
   MAP(SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
   MAP(TLS_RSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
   MAP(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
   MAP(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_DH_anon_WITH_AES_128_CBC_SHA);
   MAP(TLS_RSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
   MAP(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
   MAP(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_DH_anon_WITH_AES_256_CBC_SHA);
   MAP(TLS_ECDH_ECDSA_WITH_NULL_SHA);
   MAP(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
   MAP(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_ECDHE_ECDSA_WITH_NULL_SHA);
   MAP(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
   MAP(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_ECDH_RSA_WITH_NULL_SHA);
   MAP(TLS_ECDH_RSA_WITH_RC4_128_SHA);
   MAP(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_ECDHE_RSA_WITH_NULL_SHA);
   MAP(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
   MAP(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
   MAP(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
   MAP(TLS_ECDH_anon_WITH_NULL_SHA);
   MAP(TLS_ECDH_anon_WITH_RC4_128_SHA);
   MAP(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
   MAP(TLS_ECDH_anon_WITH_AES_256_CBC_SHA);
   MAP(TLS_NULL_WITH_NULL_NULL);
   MAP(TLS_RSA_WITH_NULL_MD5);
   MAP(TLS_RSA_WITH_NULL_SHA);
   MAP(TLS_RSA_WITH_RC4_128_MD5);
   MAP(TLS_RSA_WITH_RC4_128_SHA);
   MAP(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_RSA_WITH_NULL_SHA256);
   MAP(TLS_RSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_RSA_WITH_AES_256_CBC_SHA256);
   MAP(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_DH_DSS_WITH_AES_128_CBC_SHA256);
   MAP(TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
   MAP(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_DH_DSS_WITH_AES_256_CBC_SHA256);
   MAP(TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
   MAP(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
   MAP(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
   MAP(TLS_DH_anon_WITH_RC4_128_MD5);
   MAP(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_DH_anon_WITH_AES_128_CBC_SHA256);
   MAP(TLS_DH_anon_WITH_AES_256_CBC_SHA256);
   MAP(TLS_PSK_WITH_RC4_128_SHA);
   MAP(TLS_PSK_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_PSK_WITH_AES_128_CBC_SHA);
   MAP(TLS_PSK_WITH_AES_256_CBC_SHA);
   MAP(TLS_DHE_PSK_WITH_RC4_128_SHA);
   MAP(TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
   MAP(TLS_DHE_PSK_WITH_AES_256_CBC_SHA);
   MAP(TLS_RSA_PSK_WITH_RC4_128_SHA);
   MAP(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA);
   MAP(TLS_RSA_PSK_WITH_AES_128_CBC_SHA);
   MAP(TLS_RSA_PSK_WITH_AES_256_CBC_SHA);
   MAP(TLS_PSK_WITH_NULL_SHA);
   MAP(TLS_DHE_PSK_WITH_NULL_SHA);
   MAP(TLS_RSA_PSK_WITH_NULL_SHA);
   MAP(TLS_RSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_RSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_DH_RSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_DH_RSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
   MAP(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
   MAP(TLS_DH_DSS_WITH_AES_128_GCM_SHA256);
   MAP(TLS_DH_DSS_WITH_AES_256_GCM_SHA384);
   MAP(TLS_DH_anon_WITH_AES_128_GCM_SHA256);
   MAP(TLS_DH_anon_WITH_AES_256_GCM_SHA384);
   MAP(TLS_PSK_WITH_AES_128_GCM_SHA256);
   MAP(TLS_PSK_WITH_AES_256_GCM_SHA384);
   MAP(TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
   MAP(TLS_DHE_PSK_WITH_AES_256_GCM_SHA384);
   MAP(TLS_RSA_PSK_WITH_AES_128_GCM_SHA256);
   MAP(TLS_RSA_PSK_WITH_AES_256_GCM_SHA384);
   MAP(TLS_PSK_WITH_AES_128_CBC_SHA256);
   MAP(TLS_PSK_WITH_AES_256_CBC_SHA384);
   MAP(TLS_PSK_WITH_NULL_SHA256);
   MAP(TLS_PSK_WITH_NULL_SHA384);
   MAP(TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);
   MAP(TLS_DHE_PSK_WITH_AES_256_CBC_SHA384);
   MAP(TLS_DHE_PSK_WITH_NULL_SHA256);
   MAP(TLS_DHE_PSK_WITH_NULL_SHA384);
   MAP(TLS_RSA_PSK_WITH_AES_128_CBC_SHA256);
   MAP(TLS_RSA_PSK_WITH_AES_256_CBC_SHA384);
   MAP(TLS_RSA_PSK_WITH_NULL_SHA256);
   MAP(TLS_RSA_PSK_WITH_NULL_SHA384);
   MAP(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
   MAP(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
   MAP(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
   MAP(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
   MAP(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
   MAP(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
   MAP(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384);
   MAP(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
   MAP(SSL_RSA_WITH_RC2_CBC_MD5);
   MAP(SSL_RSA_WITH_IDEA_CBC_MD5);
   MAP(SSL_RSA_WITH_DES_CBC_MD5);
   MAP(SSL_RSA_WITH_3DES_EDE_CBC_MD5);
   MAP(SSL_NO_SUCH_CIPHERSUITE);
#undef MAP
   }
   return nullptr;
}
} // end namepsace
