/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/ssl.h>
#include <common/c++/linereader.h>
#include <common/c++/lock.h>
#include <common/c++/new.h>
#include <common/misc.h>
#include <string.h>
#include <vector>

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")

namespace {

struct SChannelFilter : public pollster::Filter
{
   PSecurityFunctionTable SecInterface;
   SecHandle context;
   CredHandle creds;
   bool handshakeComplete;
   bool server;
   std::vector<char> pendingReads;
   SecPkgContext_StreamSizes sizes;
   PWSTR remoteName;
   CRITICAL_SECTION writeLock;
   std::vector<char> pendingWrites;
   std::vector<std::pair<size_t, std::function<void(error*)>>> pendingWriteCallbacks;
   pollster::SslArgs::CallbackStruct cb;
   common::Pointer<pollster::Certificate> Certificate;

   SChannelFilter()
      : SecInterface(nullptr),
        handshakeComplete(false),
        server(false),
        remoteName(nullptr)
   {
      SecInvalidateHandle(&context);
      SecInvalidateHandle(&creds);
      memset(&sizes, 0, sizeof(sizes));
      InitializeCriticalSection(&writeLock);
   }

   ~SChannelFilter()
   {
      if (Valid(context))
         DeleteSecurityContext(&context);
      if (SecInterface && Valid(creds))
         SecInterface->FreeCredentialsHandle(&creds);
      free(remoteName);
      DeleteCriticalSection(&writeLock);
   }

   static bool
   Valid(SecHandle &handle)
   {
      // XXX: This assumes the implementation of SecInvalidateHandle()
      //
      return handle.dwLower != -1 || handle.dwUpper != -1;
   }

   void
   error_set_winsec(error *err, SECURITY_STATUS status)
   {
      if ((status & 0x80000000U))
      {
         error_set_win32(err, status);
      }
      else if (status)
      {
         error_clear(err);
         memcpy(&err->source, "wsec", MIN(sizeof(err->source), 4));
         err->code = status;
      }
   }

   void
   GetCreds(bool server, error *err)
   {
      SECURITY_STATUS status = 0;
      TimeStamp ts = {0};
      SCHANNEL_CRED cred = {0};
      PCCERT_CONTEXT certContext = nullptr;

      if (Valid(creds))
         goto exit;

      cred.dwVersion = SCHANNEL_CRED_VERSION;

      if (Certificate.Get())
      {
         certContext = (PCCERT_CONTEXT)Certificate->GetNativeObject();

         cred.cCreds = 1;
         cred.paCred = &certContext;
      }

      if (!server)
      {
         if (!remoteName)
            cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
         else
            cred.dwFlags |= SCH_CRED_AUTO_CRED_VALIDATION;
      }

      status = SecInterface->AcquireCredentialsHandle(
         nullptr,
         UNISP_NAME,
         server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
         nullptr,
         &cred,
         nullptr,
         nullptr,
         &creds,
         &ts
      );
      if (status)
         ERROR_SET(err, winsec, status);
   exit:;
   }

   void
   Initialize(pollster::SslArgs &args, error *err)
   {
      this->server = args.ServerMode;
      Certificate = args.Certificate;

      cb = std::move(args.Callbacks);

      SecInterface = InitSecurityInterface();
      if (!SecInterface)
         ERROR_SET(err, win32, GetLastError());

      if (args.HostName)
      {
         remoteName = ConvertToPwstr(args.HostName, err);
         ERROR_CHECK(err);
      }

      GetCreds(server, err);
      ERROR_CHECK(err);
   exit:;
   }

   void
   TryHandshake(const void *&buf, size_t &len, error *err)
   {
      SECURITY_STATUS status = 0;
      DWORD flagsOut = 0;
      TimeStamp ts = {0};
      size_t pad = 0;

      SecBufferDesc input = {0}, output = {0};

      SecBuffer inputBufs[2] = {0};
      SecBuffer outputBuf = {0};

      bool completedHere = false;

      if (handshakeComplete)
         goto exit;

      if (buf && len)
      {
         input.ulVersion = SECBUFFER_VERSION;
         input.cBuffers = 2;
         input.pBuffers = inputBufs;

         auto in = inputBufs;
         in->BufferType = SECBUFFER_TOKEN;
         in->pvBuffer = (void*)buf;
         in->cbBuffer = len;
         pad = len - in->cbBuffer;
         ++in;
         in->BufferType = SECBUFFER_EMPTY;
      }

      output.ulVersion = SECBUFFER_VERSION;
      output.cBuffers = 1;
      output.pBuffers = &outputBuf;

      outputBuf.BufferType = SECBUFFER_TOKEN;

      if (server)
      {
         status = SecInterface->AcceptSecurityContext(
            &creds,
            Valid(context) ? &context : nullptr,
            (buf && len) ? &input : nullptr,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
               ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            SECURITY_NATIVE_DREP,
            Valid(context) ? nullptr : &context,
            &output,
            &flagsOut,
            &ts
         );
      }
      else
      {
         status = SecInterface->InitializeSecurityContext(
            &creds,
            Valid(context) ? &context : nullptr,
            remoteName,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
               ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            0,
            SECURITY_NATIVE_DREP,
            (buf && len) ? &input : nullptr,
            0,
            Valid(context) ? nullptr : &context,
            &output,
            &flagsOut,
            &ts
         );
      }

      if (buf && len)
      {
         if (inputBufs[1].BufferType == SECBUFFER_EXTRA)
         {
            buf = (char*)buf + (DWORD)len - inputBufs[1].cbBuffer;
            len = inputBufs[1].cbBuffer + pad;
         }
         else if (status != SEC_E_INCOMPLETE_MESSAGE)
         {
            if (pad)
            {
               buf = (char*)buf + (DWORD)len;
               len = pad;
            }
            else
            {
               buf = nullptr;
               len = 0;
            }
         }
      }

      switch (status)
      {
      case SEC_E_OK:
         completedHere = true;
         break;
      case SEC_I_CONTINUE_NEEDED:
      case SEC_E_INCOMPLETE_MESSAGE:
         break;
      default:
         ERROR_SET(err, winsec, status);
      }

      if (outputBuf.cbBuffer && Events.get())
      {
         Events->OnBytesToWrite(outputBuf.pvBuffer, outputBuf.cbBuffer, std::function<void(error*)>());
      }

      if (completedHere)
      {
         common::locker l;

         if (cb.OnCipherKnown)
         {
            SecPkgContext_CipherInfo info = {0};
            PSTR name = nullptr;

            status = SecInterface->QueryContextAttributes(
               &context,
               SECPKG_ATTR_CIPHER_INFO,
               &info
            );
            if (status)
               ERROR_SET(err, winsec, status);

            name = ConvertToPstr(info.szCipherSuite, err);
            ERROR_CHECK(err);

            cb.OnCipherKnown(name, err);
            free(name);
            ERROR_CHECK(err);
         }

         l.acquire(&writeLock);
         handshakeComplete = true;

         if (pendingWrites.size())
         {
            int i = 0;
            size_t n = 0;

            while (n < pendingWrites.size())
            {
               auto p = (i<pendingWriteCallbacks.size()) ? &pendingWriteCallbacks[i++] : nullptr;
               auto m = (p ? p->first : pendingWrites.size()) - n;
               std::function<void(error *)> emptyFn;
               std::function<void(error *)> &fn = p ? p->second : emptyFn;
               Write(pendingWrites.data() + n, m, fn);
               n += m;
            }

            pendingWrites.resize(0);
            pendingWrites.shrink_to_fit();
            pendingWriteCallbacks.resize(0);
            pendingWriteCallbacks.shrink_to_fit();
         }
      }

   exit:
      if (outputBuf.pvBuffer)
         SecInterface->FreeContextBuffer(outputBuf.pvBuffer);
   }

   bool
   TryDecrypt(void *&buf, size_t &len, error *err)
   {
      SECURITY_STATUS status = 0;
      SecBuffer inputBufs[4] = {0}, *in = inputBufs;
      SecBufferDesc input = {0};
      bool found = false;
      bool eof = false;
      size_t pad = 0;

      in->BufferType = SECBUFFER_DATA;
      in->pvBuffer = buf;
      in->cbBuffer = len;
      pad = len - in->cbBuffer;
      ++in;

      for (int i=0; i<3; ++i)
         (in++)->BufferType = SECBUFFER_EMPTY;

      input.ulVersion = SECBUFFER_VERSION;
      input.cBuffers = in - inputBufs;
      input.pBuffers = inputBufs;

      status = SecInterface->DecryptMessage(&context, &input, 0, nullptr);
      switch (status)
      {
      case SEC_I_RENEGOTIATE:
         handshakeComplete = false;
         break;
      case SEC_E_INCOMPLETE_MESSAGE:
         goto exit;
      case SEC_E_OK:
         found = true;
         break;
      case SEC_I_CONTEXT_EXPIRED:
         eof = true;
         break;
      default:
         ERROR_SET(err, winsec, status);
      }

      if ((in = &inputBufs[1])->BufferType == SECBUFFER_DATA && Events.get())
      {
         Events->OnBytesReceived(in->pvBuffer, in->cbBuffer, err);
         ERROR_CHECK(err);
      }
      if ((in = &inputBufs[3])->BufferType == SECBUFFER_EXTRA)
      {
         buf = (char*)buf + (DWORD)len - in->cbBuffer;
         len = in->cbBuffer + pad;
      }
      else if (pad)
      {
         buf = (char*)buf + (DWORD)len;
         len = pad;
      }
      else
      {
         buf = nullptr;
         len = 0;
      }

      if (eof && Events.get())
      {
         Events->OnClosed(err);
         ERROR_CHECK(err);
      }

   exit:
      return found;
   }

   void
   Write(const void *buf, size_t len, const std::function<void(error*)> &onComplete)
   {
      error err;
      SECURITY_STATUS status = 0;
      SecBuffer outputBufs[4] = {0}, *out = outputBufs;
      SecBufferDesc output = {0};
      size_t msglen = 0;
      std::vector<char> tmp;
      common::locker l;

      if (!sizes.cbMaximumMessage)
      {
         l.acquire(&writeLock);

         if (!handshakeComplete)
            goto noContext;

         status = SecInterface->QueryContextAttributes(
            &context,
            SECPKG_ATTR_STREAM_SIZES,
            &sizes
         );

         l.release();

         if (status)
            ERROR_SET(&err, winsec, status);
      }

      while (len > sizes.cbMaximumMessage)
      {
         auto n = sizes.cbMaximumMessage;
         Write(buf, n, std::function<void(error*err)>());
         buf = (const char*)buf + n;
         len -= n;
      }

      out->BufferType = SECBUFFER_STREAM_HEADER;
      msglen += (out->cbBuffer = sizes.cbHeader);
      ++out;
      out->BufferType = SECBUFFER_DATA;
      msglen += (out->cbBuffer = len);
      ++out;
      out->BufferType = SECBUFFER_STREAM_TRAILER;
      msglen += (out->cbBuffer = sizes.cbTrailer);
      ++out;
      out->BufferType = SECBUFFER_EMPTY;
      ++out;

      output.ulVersion = SECBUFFER_VERSION;
      output.cBuffers = out - outputBufs;
      output.pBuffers = outputBufs;

      try
      {
         tmp.resize(msglen);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(&err, nomem);
      }

      out = outputBufs;
      out->pvBuffer = tmp.data();
      for (++out; out->BufferType != SECBUFFER_EMPTY; ++out)
      {
         auto &prev = out[-1];
         out->pvBuffer = (char*)prev.pvBuffer + prev.cbBuffer;
      }

      memcpy(outputBufs[1].pvBuffer, buf, len);

      l.acquire(&writeLock);

      if (!handshakeComplete)
      {
      noContext:
         tmp.resize(0);
         tmp.shrink_to_fit();

         try
         {
            pendingWrites.insert(pendingWrites.end(), (char*)buf, (char*)buf+len);
            if (onComplete)
               pendingWriteCallbacks.push_back(std::make_pair(pendingWrites.size(), onComplete));
         }
         catch (std::bad_alloc)
         {
            l.release();
            ERROR_SET(&err, nomem);
         }
         goto exit;
      }

      status = SecInterface->EncryptMessage(&context, 0, &output, 0);
      if (status)
         ERROR_SET(&err, winsec, status);

      if (Events.get())
         Events->OnBytesToWrite(tmp.data(), tmp.size(), onComplete);

   exit:
      if (ERROR_FAILED(&err) && Events.get())
      {
         Events->OnAsyncError(&err);
      }
   }

   void
   OnBytesReceived(const void *buf, size_t len, error *err)
   {
      bool heap = false;

      if (pendingReads.size())
      {
         try
         {
            pendingReads.insert(pendingReads.end(), (char*)buf, (char*)buf+len);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
         buf = pendingReads.data();
         len = pendingReads.size();
         heap = true;
      }

   retry:
      if (!handshakeComplete)
      {
         size_t slen = len;
         TryHandshake(buf, slen, err);
         ERROR_CHECK(err);
         len = slen;

         if (len && handshakeComplete)
            goto recvPath;
      }
      else
      {
      recvPath:
         bool shouldRetry = false;

         void *sbuf = (void*)buf;
         size_t slen = len;

         shouldRetry = TryDecrypt(sbuf, slen, err);
         ERROR_CHECK(err);
         buf = sbuf;
         len = slen;

         if ((shouldRetry || !handshakeComplete) && len)
            goto retry;
      }

      if (heap)
         pendingReads.erase(pendingReads.begin(), pendingReads.begin() + pendingReads.size() - len);
      else if (len)
      {
         try
         {
            pendingReads.insert(pendingReads.end(), (char*)buf, (char*)buf+len);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      }
   exit:;
   }

   void
   OnEof()
   {
   }

   void
   OnEventsInitialized(error *err)
   {
      if (!server)
      {
         const void *buf = nullptr;
         size_t len = 0;

         TryHandshake(buf, len, err);
      }
   }
};

struct Win32Cert : public pollster::Certificate
{
   PCCERT_CONTEXT ctx;

   Win32Cert() : ctx(nullptr) {}
   ~Win32Cert() { if (ctx) CertFreeCertificateContext(ctx); }

   void *GetNativeObject() { return (void*)ctx; }

   void
   Create(DWORD encoding, const void *buf, size_t len, error *err)
   {
      if (len > ((DWORD)~0U))
         ERROR_SET(err, unknown, "Too big for dword length");
      if (ctx)
         CertFreeCertificateContext(ctx);
      ctx = CertCreateCertificateContext(encoding, (PBYTE)buf, (DWORD)len);
      if (!ctx)
         ERROR_SET(err, win32, GetLastError());
   exit:;
   }
};

struct Win32Store
{
   HCERTSTORE store;

   Win32Store() : store(nullptr) {}
   Win32Store(const Win32Store&) = delete;
   ~Win32Store() { if (store) CertCloseStore(store, 0); }
};

} // end namespace

void
pollster::CreateSslFilter(
   SslArgs &args,
   std::shared_ptr<pollster::Filter> &res,
   error *err
)
{
   SChannelFilter *f = nullptr;
   try
   {
      f = new SChannelFilter();
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

void
pollster::InitSslLibrary(error *err)
{
}

template<typename Callback>
static
void
ParsePemFile(
   common::Stream *stream,
   Callback onSection,
   error *err
)
{
   common::LineReader lineReader(stream);
   char *line = nullptr;
   std::string currentItem;
   std::string payload;
   std::vector<unsigned char> payloadDecoded;

   while ((line = lineReader.ReadLine(err)))
   {
      static const char dashes[] = "-----";
      size_t len = strlen(line);

      while (len && strchr(" \t", line[len-1]))
      {
         line[--len] = 0;
      }

      if (!*line)
         continue;

      if (len > sizeof(dashes)-1 &&
          !strcmp(line+len-(sizeof(dashes)-1), dashes) &&
          !strncmp(line, dashes, sizeof(dashes)-1))
      {
         line += sizeof(dashes)-1;
         len -= (sizeof(dashes) - 1) * 2;
         line[len] = 0;

         static const char begin[] = "BEGIN ";
         static const char end[] = "END ";

         if (!strncmp(line, begin, sizeof(begin)-1))
         {
            line += sizeof(begin)-1;
            len -= sizeof(begin)-1;

            if (currentItem.size())
               ERROR_SET(err, unknown, "BEGIN without END");
            try
            {
               currentItem = line;
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }
         }
         else if (!strncmp(line, end, sizeof(end)-1))
         {
            line += sizeof(end)-1;
            len -= sizeof(end)-1;

            if (!*line || currentItem != line)
               ERROR_SET(err, unknown, "Mismatched BEGIN and END");

            try
            {
               payloadDecoded.resize(payload.size() / 3 * 4);
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }

            if (payloadDecoded.size() > (DWORD)~0U)
               ERROR_SET(err, unknown, "Payload too big");

            DWORD len = payloadDecoded.size();
            auto ret = CryptStringToBinaryA(
               payload.c_str(),
               payload.size(),
               CRYPT_STRING_BASE64,
               payloadDecoded.data(),
               &len,
               nullptr,
               nullptr
            );
            if (!ret)
               ERROR_SET(err, nomem);

            payload.resize(0);

            onSection(currentItem, payloadDecoded.data(), len, err);
            ERROR_CHECK(err);
            currentItem.resize(0);
         }
         else
         {
            ERROR_SET(err, unknown, "Malformed line");
         }
      }
      else if (currentItem.size())
      {
         try
         {
            payload += line;
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      }
   }
   ERROR_CHECK(err);
exit:;
}

void
pollster::CreateCertificate(
   common::Stream *stream,
   Certificate **output,
   error *err
)
{
   common::Pointer<Win32Cert> r;
   Win32Store store;
   const DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

   store.store = CertOpenStore(CERT_STORE_PROV_MEMORY, encoding, 0, 0, nullptr);
   if (!store.store)
      ERROR_SET(err, win32, GetLastError());

   common::New(r, err);
   ERROR_CHECK(err);

   ParsePemFile(
      stream,
      [&] (const std::string &label, const void *payload, DWORD len, error *err) -> void
      {
         static const char certLabel[] = "CERTIFICATE";
         static const char rsaKeyLabel[] = "RSA PRIVATE KEY";
         static const char pkcs8Label[] = "PRIVATE KEY";

         HCRYPTPROV prov = 0;
         HCRYPTKEY hkey = 0;
         PCRYPT_PRIVATE_KEY_INFO privateKeyInfo = nullptr;
         PVOID keyData = nullptr;
         DWORD keyLen = 0;

         if (label.size() == sizeof(certLabel)-1 && label == certLabel)
         {
            auto ret = CertAddEncodedCertificateToStore(
               store.store,
               encoding,
               (const BYTE*)payload,
               len,
               CERT_STORE_ADD_USE_EXISTING,
               r->ctx ? nullptr : &r->ctx
            );
            if (!ret)
               ERROR_SET(err, win32, GetLastError());
         }
         else if (label.size() == sizeof(rsaKeyLabel)-1 && label == rsaKeyLabel)
         {
         rsaKey:
            auto ret = CryptDecodeObjectEx(
               encoding,
               PKCS_RSA_PRIVATE_KEY,
               (const BYTE*)payload,
               len,
               CRYPT_DECODE_ALLOC_FLAG,
               nullptr,
               &keyData,
               &keyLen
            );
            if (!ret)
               ERROR_SET(err, win32, GetLastError());
         }
         else if (label.size() == sizeof(pkcs8Label)-1 && label == pkcs8Label)
         {
            DWORD privateKeyInfoLen = 0;
            auto ret = CryptDecodeObjectEx(
               X509_ASN_ENCODING,
               PKCS_PRIVATE_KEY_INFO,
               (const BYTE*)payload,
               len,
               CRYPT_DECODE_ALLOC_FLAG,
               nullptr,
               &privateKeyInfo,
               &privateKeyInfoLen
            );
            if (!ret)
               ERROR_SET(err, win32, GetLastError());

            static const char rsaOid[] = szOID_RSA;
            if (!strncmp(privateKeyInfo->Algorithm.pszObjId, rsaOid, sizeof(rsaOid)-1))
            {
               payload = privateKeyInfo->PrivateKey.pbData;
               len = privateKeyInfo->PrivateKey.cbData;
               goto rsaKey;
            }
            else
            {
               // TODO: decode X509_ECC_PRIVATE_KEY into CRYPT_ECC_PRIVATE_KEY_INFO struct.
               // this will ultimately require some CNG work.
               //
               ERROR_SET(err, unknown, "Presumed ECC cert?  Not supported at present.");
            }
         }
         else
         {
            ERROR_SET(err, unknown, "Unrecognized label");
         }

         if (keyData)
         {
            WCHAR token[256] = L"libpollster:";
            PWSTR suffix = token + wcslen(token);
            static WCHAR provName[] = MS_STRONG_PROV_W;
            auto provType = PROV_RSA_FULL;
            static LONG ctr = 0;

            _snwprintf(
               suffix,
               ARRAY_SIZE(token) - (suffix-token),
               L"%d,%d",
               GetCurrentProcessId(),
               InterlockedIncrement(&ctr)
            );

            CryptAcquireContext(&prov, token, provName, provType, CRYPT_DELETEKEYSET);
            if (!CryptAcquireContext(&prov, token, provName, provType, CRYPT_NEWKEYSET))
               ERROR_SET(err, win32, GetLastError());
            if (!CryptImportKey(prov, (const BYTE*)keyData, keyLen, 0, CRYPT_EXPORTABLE, &hkey))
               ERROR_SET(err, win32, GetLastError());
            if (!CertSetCertificateContextProperty(r->ctx, CERT_KEY_PROV_HANDLE_PROP_ID, 0, &prov))
               ERROR_SET(err, win32, GetLastError());

            CRYPT_KEY_PROV_INFO provInfo = {0};

            provInfo.pwszContainerName = token;
            provInfo.pwszProvName = provName;
            provInfo.dwProvType = provType;
            provInfo.dwKeySpec = AT_KEYEXCHANGE;

            if (!CertSetCertificateContextProperty(r->ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &provInfo))
               ERROR_SET(err, win32, GetLastError());
         }

      exit:
         if (privateKeyInfo)
            LocalFree(privateKeyInfo);
         if (keyData)
            LocalFree(keyData);
         if (hkey)
            CryptDestroyKey(hkey);
         if (prov)
            CryptReleaseContext(prov, 0);
      },
      err
   );
   ERROR_CHECK(err);

exit:
   if (ERROR_FAILED(err))
      r = nullptr;
   *output = r.Detach();
}
