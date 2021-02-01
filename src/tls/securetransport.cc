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
#include <common/c++/new.h>
#include <common/misc.h>

#include <sys/stat.h>
#include <unistd.h>

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

      struct stat statbuf;
      if (stat("/dev/random", &statbuf))
         ERROR_SET(err, unknown, "SecureTransport does not work without /dev/random");

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

      if (args.Certificate.Get())
      {
         status = SSLSetCertificate(ssl, (CFArrayRef)args.Certificate->GetNativeObject());
         if (status)
            ERROR_SET(err, osstatus, status);
      }

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
         catch (const std::bad_alloc&)
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
         catch (const std::bad_alloc&)
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
         catch (const std::bad_alloc&)
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

void
pollster::InitSslLibrary(error *err)
{
}

namespace {

struct SecItemCert : public pollster::Certificate
{
   CFArrayRef ref;

   SecItemCert() : ref(nullptr) {}

   ~SecItemCert()
   {
      if (ref)
         CFRelease(ref);
   }

   void *
   GetNativeObject() { return (void*)ref; }
};

} // end namespace

static
CFStringRef
WrapStringLiteral(
   const char *str,
   error *err
)
{
   auto r = CFStringCreateWithBytesNoCopy(
      nullptr,
      (const UInt8*)str,
      strlen(str),
      kCFStringEncodingUTF8,
      false,
      kCFAllocatorNull
   );
   if (!r)
      error_set_nomem(err);
   return r;
}

static
CFDataRef
ReadIntoData(common::Stream *stream, error *err)
{
   char buf[4096];
   CFMutableDataRef data = nullptr;
   int64_t length = 0;

   length = stream->GetSize(err);
   ERROR_CHECK(err);
   length -= stream->GetPosition(err);
   ERROR_CHECK(err);

   if (length > LONG_MAX)
      ERROR_SET(err, unknown, "Length too long for CFData!");

   data = CFDataCreateMutable(nullptr, length);
   if (!data)
      ERROR_SET(err, nomem);

   for (;;)
   {
      auto r = stream->Read(buf, sizeof(buf), err);
      ERROR_CHECK(err);
      if (r <= 0)
         break;

      CFDataAppendBytes(data, (const UInt8*)buf, r);
   }
exit:
   if (ERROR_FAILED(err) && data)
   {
      CFRelease(data);
      data = nullptr;
   }
   return data;
}

extern "C" {
SecIdentityRef
SecIdentityCreate(
   CFAllocatorRef allocator,
   SecCertificateRef certificate,
   SecKeyRef privateKey
);
}

void
pollster::CreateCertificate(
   common::Stream *stream,
   Certificate **output,
   error *err
)
{
   common::Pointer<SecItemCert> r;
   OSStatus status = 0;
   CFDataRef data = nullptr;
   CFStringRef extension = nullptr;
   SecExternalFormat inputFormat = kSecFormatPEMSequence;
   SecExternalItemType itemType = kSecItemTypeAggregate;
   SecItemImportExportKeyParameters keyParams = {0};
   CFIndex nItems = 0;
   const void *firstItem = nullptr;
   CFTypeID typeId;
   SecIdentityRef identity = nullptr;

   common::New(r, err);
   ERROR_CHECK(err);

   data = ReadIntoData(stream, err);
   ERROR_CHECK(err);

   extension = WrapStringLiteral(".pem", err);
   ERROR_CHECK(err);

   status = SecItemImport(
      data,
      extension,
      &inputFormat,
      &itemType,
      0,
      &keyParams,
      nullptr,
      &r->ref
   );
   if (status)
      ERROR_SET(err, osstatus, status);

   nItems = CFArrayGetCount(r->ref);
   if (!nItems)
      ERROR_SET(err, unknown, "Empty list");

   firstItem = CFArrayGetValueAtIndex(r->ref, 0);
   typeId = CFGetTypeID(firstItem);
   if (typeId != SecIdentityGetTypeID())
   {
      SecKeyRef key = nullptr;
      std::vector<const void *> newArr;

      if (typeId != SecCertificateGetTypeID())
         ERROR_SET(err, unknown, "Expected certificate as first member");

      try
      {
         newArr.push_back(nullptr);
      }
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }

      for (CFIndex i=1; i<nItems; ++i)
      {
         auto p = CFArrayGetValueAtIndex(r->ref, i);
         if (CFGetTypeID(p) == SecKeyGetTypeID())
         {
            if (key)
               ERROR_SET(err, unknown, "Unexpected: multiple private keys");
            key = (SecKeyRef)p;
            continue;
         }

         try
         {
            newArr.push_back(p);
         }
         catch (const std::bad_alloc&)
         {
            ERROR_SET(err, nomem);
         }
      }

      if (!key)
         ERROR_SET(err, unknown, "Cannot find key");

      identity = SecIdentityCreate(
         nullptr,
         (SecCertificateRef)firstItem,
         key
      );
      if (!identity)
         ERROR_SET(err, unknown, "Cannot create identity");
      newArr[0] = identity;

      auto newCfArr = CFArrayCreate(
         nullptr,
         newArr.data(),
         newArr.size(),
         &kCFTypeArrayCallBacks
      );
      if (!newCfArr)
         ERROR_SET(err, nomem);

      CFRelease(r->ref);
      r->ref = newCfArr;
   }

exit:
   if (data)
      CFRelease(data);
   if (extension)
      CFRelease(extension);
   if (identity)
      CFRelease(identity);
   if (ERROR_FAILED(err))
      r = nullptr;
   *output = r.Detach();
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
