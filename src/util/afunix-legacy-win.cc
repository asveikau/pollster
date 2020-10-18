/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// This file attempts to provide functionality similar to Unix domain
// sockets for older builds of Windows (circa build 17000-something and
// earlier).  It works via named pipes.
//
// Server provides two named pipes:
//    \\.\pipe\SocketName
//       When you read from that it will give you an "nnn" to connect
//       to.
//    \\.\pipe\SocketName-nnn
//       Specific peer instance, where nnn is provided in above step.
//

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <pollster/win.h>

#include <common/misc.h>
#include <common/path.h>
#include <common/crypto/rng.h>
#include <string.h>

namespace {

#define ILLEGAL_CHARS   "/\\:<>|*?\""
#define CONCAT2(X,Y)    X##Y
#define CONCAT(X,Y)     CONCAT2(X,Y)
#define ILLEGAL_CHARS_W CONCAT(L, ILLEGAL_CHARS)

PWSTR
ConvertPipeName(struct sockaddr_un *sa, error *err)
{
   PWSTR r = nullptr;
   const char *pipeName = nullptr;
   const char *prefix = "";
   char *r8 = nullptr;
   char *buf = nullptr;
   char *p = nullptr;

   pipeName = sa->sun_path;
   if (!*pipeName)
   {
      ++pipeName;
      prefix = "abs-";
   }
   else
   {
      buf = make_absolute_path(pipeName, err);
      ERROR_CHECK(err);
      if (buf)
         pipeName = buf;
   }

   // Make writeable copy of path...
   //
   if (!buf)
   {
      buf = _strdup(pipeName);
      if (!buf)
         ERROR_SET(err, nomem);
   }

   // Filter out invalid chars
   //
   p = buf;
   while ((p = strpbrk(p, ILLEGAL_CHARS)))
   {
      *p++ = '-';
   }
   pipeName = buf;

   if (-1 == asprintf(&r8, "\\\\.\\pipe\\plstr-%s%s", prefix, pipeName))
      ERROR_SET(err, nomem);

   r = ConvertToPwstr(r8, err);
   ERROR_CHECK(err);

exit:
   if (ERROR_FAILED(err))
   {
      free(r);
      r = nullptr;
   }
   free(r8);
   free(buf);
   return r;
}

} // end namespace

static void
AfUnixServerLoop(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::wstring &pipeName,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
);

static void
WaitForClient(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::function<void(error *err)> &onConnect,
   error *err
);

static void
AfUnixServerHelloWritten(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::wstring &pipeName,
   const std::shared_ptr<common::FileHandle> &childPipe,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
)
{
   //
   // When the client connects to the child pipe, notify the caller, and
   // restart the server loop on the primary pipe.
   //

   DisconnectNamedPipe(pipe->Get());

   WaitForClient(
      w,
      childPipe,
      [w, pipe, pipeName, childPipe, on_client] (error *err) -> void
      {
         on_client(childPipe, err);
         ERROR_CHECK(err);

      exit:
         error_clear(err);
         AfUnixServerLoop(w, pipe, pipeName, on_client, err);
         ERROR_CHECK(err);
      },
      err
   );
   ERROR_CHECK(err);

exit:;
}

#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

static
PSECURITY_DESCRIPTOR
CreateDenyNetworkAcl(std::function<void()> &free_fn, error *err)
{
   PACL acl = nullptr;
   DWORD cbAcl = 0;
   PSID networkSid = nullptr;
   DWORD cbNetworkSid = 0;
   PSECURITY_DESCRIPTOR sd = nullptr;
   common::FileHandle userToken;
   union
   {
      TOKEN_USER user;
      char buffer[4096];
   } tokenUser;
   PSID userSid = nullptr;

   networkSid = (PSID)malloc(cbNetworkSid = SECURITY_MAX_SID_SIZE);
   if (!networkSid)
      ERROR_SET(err, nomem);

   if (!CreateWellKnownSid(WinNetworkSid, nullptr, networkSid, &cbNetworkSid))
      ERROR_SET(err, win32, GetLastError());

   {
      DWORD dummy = 0;
      HANDLE tokenHandle = INVALID_HANDLE_VALUE;
      if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
         ERROR_SET(err, win32, GetLastError());
      userToken = tokenHandle;

      if (!GetTokenInformation(tokenHandle, TokenUser, &tokenUser,
              sizeof(tokenUser), &dummy))
         ERROR_SET(err, win32, GetLastError());

      userSid = tokenUser.user.User.Sid;
   }

   cbAcl = sizeof(*acl);
   cbAcl += sizeof(ACCESS_DENIED_ACE) + GetLengthSid(networkSid) - sizeof(DWORD);
   cbAcl += sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(userSid) - sizeof(DWORD);
   cbAcl = (cbAcl + 3) / 4 * 4;

   acl = (PACL)malloc(cbAcl);
   if (!acl)
      ERROR_SET(err, nomem);

   if (!InitializeAcl(acl, cbAcl, ACL_REVISION))
      ERROR_SET(err, win32, GetLastError());

   if (!AddAccessDeniedAce(acl, ACL_REVISION, GENERIC_ALL, networkSid))
      ERROR_SET(err, win32, GetLastError());

   if (!AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, userSid))
      ERROR_SET(err, win32, GetLastError());

   sd = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
   if (!sd)
      ERROR_SET(err, win32, GetLastError());

   if (!InitializeSecurityDescriptor(sd, SDDL_REVISION_1))
      ERROR_SET(err, win32, GetLastError());

   if (!SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE))
      ERROR_SET(err, win32, GetLastError());

exit:
   free_fn = [networkSid, acl, sd] () -> void
   {
      free(networkSid);
      free(acl);
      free(sd);
   };
   if (ERROR_FAILED(err))
   {
      free_fn();
      free_fn = [] () -> void {};
      sd = nullptr;
   }
   return sd;
}

static void
CreateNamedPipe(
   std::shared_ptr<common::FileHandle> &pipe,
   PCWSTR name,
   DWORD access,
   bool checkError,
   error *err
)
{
   PSECURITY_DESCRIPTOR sd = nullptr;
   SECURITY_ATTRIBUTES attrs = {0};
   DWORD flags = 0;
   std::function<void(void)> free_acl = [] () -> void {};

   if (!pipe)
   {
      try
      {
         pipe = std::make_shared<common::FileHandle>();
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   }

   sd = CreateDenyNetworkAcl(free_acl, err);
   ERROR_CHECK(err);

   attrs.nLength = sizeof(attrs);
   attrs.lpSecurityDescriptor = sd;

#if 0 // Needs Vista+
   flags |= PIPE_REJECT_REMOTE_CLIENTS;
#endif

   *pipe = CreateNamedPipe(
      name,
      access | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
      flags | PIPE_TYPE_BYTE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      0,
      0,
      0,
      &attrs
   );
   if (checkError && !pipe->Valid())
      ERROR_SET(err, win32, GetLastError());
exit:
   DWORD error = GetLastError();
   free_acl();
   SetLastError(error);
}

static void
CreateNamedPipe(
   std::shared_ptr<common::FileHandle> &pipe,
   PCWSTR name,
   DWORD access,
   error *err
)
{
   return CreateNamedPipe(pipe, name, access, true, err);
}

static void
AfUnixServerConnected(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::wstring &pipeName,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
)
{
   //
   // A client connected to the primary pipe.  Create a random child pipe
   // and tell the client about it.
   //

   std::shared_ptr<common::FileHandle> childPipe;
   rng_state *rng = nullptr;
   struct
   {
      USHORT len;
      WCHAR suffix[16];
   } resp;
   std::shared_ptr<std::vector<unsigned char>> respHeap;

   try
   {
      childPipe = std::make_shared<common::FileHandle>();
      respHeap = std::make_shared<std::vector<unsigned char>>();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   rng_init(&rng, err);
   ERROR_CHECK(err);

   while (!childPipe->Valid())
   {
      PWSTR p = resp.suffix;
      unsigned char buf[(ARRAY_SIZE(resp.suffix) - 1)/2];
      const unsigned char *q = buf;
      static unsigned char digits[] = "0123456789abcdef";
      std::wstring nextName;

      rng_generate(rng, buf, sizeof(buf), err);
      ERROR_CHECK(err);

      while (q < buf+sizeof(buf))
      {
         *p++ = digits[((*q) >> 4) & 0xf];
         *p++ = digits[(*q++) & 0xf];
      }

      *p = 0;

      try
      {
         nextName = pipeName + L"_" + resp.suffix;
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      CreateNamedPipe(
         childPipe,
         nextName.c_str(),
         PIPE_ACCESS_DUPLEX,
         false,
         err
      );
      ERROR_CHECK(err);
      if (!childPipe->Valid())
      {
         DWORD error = GetLastError();

         switch (error)
         {
         case ERROR_ACCESS_DENIED:
            break;
         default:
            ERROR_SET(err, win32, GetLastError());
         }
      }
   }

   resp.len = wcslen(resp.suffix) * sizeof(WCHAR);

   try
   {
      auto p = (const unsigned char*)&resp;
      respHeap->insert(respHeap->begin(), p, p+2+resp.len);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   pollster::windows::WriteFileAsync(
      w.Get(),
      pipe,
      nullptr,
      respHeap->data(),
      respHeap->size(),
      [w, pipe, pipeName, on_client] (error *err) -> void
      {
         if (err->source == ERROR_SRC_COM &&
             err->code == HRESULT_FROM_WIN32(ERROR_NO_DATA))
         {
            DisconnectNamedPipe(pipe->Get());
         }
         error_clear(err);

         AfUnixServerLoop(w, pipe, pipeName, on_client, err);
      },
      [respHeap, w, pipe, pipeName, childPipe, on_client] (DWORD res, error *err) -> void
      {
         AfUnixServerHelloWritten(
            w,
            pipe,
            pipeName,
            childPipe,
            on_client,
            err
         );
      }
   );

exit:
   rng_close(rng);
}

static void
WaitForClient(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::function<void(error *err)> &onConnect,
   error *err
)
{
   OVERLAPPED *ol = nullptr;

   pollster::windows::CreateOverlapped(
      w.Get(),
      std::function<void(error*)>(),
      [onConnect] (DWORD res, OVERLAPPED *ol, error *err) -> void
      {
         onConnect(err);
      },
      &ol,
      nullptr,
      err
   );
   ERROR_CHECK(err);

   if (!ConnectNamedPipe(pipe->Get(), ol))
   {
      DWORD error = GetLastError();
      switch (error)
      {
      case ERROR_PIPE_CONNECTED:
         break;
      case ERROR_IO_PENDING:
         ol = nullptr;
         break;
      default:
         ERROR_SET(err, win32, error);
      }
   }

   if (ol)
   {
      onConnect(err);
      ERROR_CHECK(err);
   }

exit:
   pollster::windows::FreeOverlapped(ol);
}

static void
AfUnixServerLoop(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::wstring &pipeName,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
)
{
   WaitForClient(
      w,
      pipe,
      [w, pipe, pipeName, on_client] (error *err) -> void
      {
         AfUnixServerConnected(w, pipe, pipeName, on_client, err);
      },
      err
   );
   ERROR_CHECK(err);

exit:;
}

void
pollster::windows::CreateLegacyAfUnixServer(
   waiter *w,
   struct sockaddr_un *sun,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
)
{
   PWSTR pipeName = nullptr;
   std::shared_ptr<common::FileHandle> mainPipe;
   common::Pointer<waiter> wp = w;
   std::wstring pipeNameObj;

   if (!w)
   {
      pollster::get_common_queue(wp.GetAddressOf(), err);
      ERROR_CHECK(err);

      w = wp.Get();
   }

   pipeName = ConvertPipeName(sun, err);
   ERROR_CHECK(err);

   try
   {
      pipeNameObj = pipeName;
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   CreateNamedPipe(
      mainPipe,
      pipeName,
      PIPE_ACCESS_OUTBOUND,
      err
   );
   ERROR_CHECK(err);

   AfUnixServerLoop(wp, mainPipe, pipeNameObj, on_client, err);
   ERROR_CHECK(err);

exit:
   free(pipeName);
}

static void
AfUnixClientHello(
   const common::Pointer<pollster::waiter> &w,
   const void *buffer,
   size_t len,
   const std::shared_ptr<common::FileHandle> &pipe,
   const std::wstring &pipeName,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
)
{
   std::wstring childPipeName;
   std::wstring suffix;
   USHORT payloadLen;

   // Need to do this early, as we don't want to be connected to the
   // main pipe when the server sees ConnectNamedPipe() complete on
   // the child and re-sets the server loop.
   //
   pipe->Reset();

   if (len < sizeof(payloadLen))
      ERROR_SET(err, unknown, "Response too small");

   payloadLen = *(const USHORT*)buffer;

   len -= sizeof(payloadLen);
   buffer = (const char*)buffer + sizeof(payloadLen);

   if (payloadLen > len)
      ERROR_SET(err, unknown, "Payload length exceeds buffer size");

   try
   {
      suffix.insert(0, (PCWSTR)buffer, payloadLen/sizeof(WCHAR));
      childPipeName = pipeName + L"_" + suffix;
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   if (wcspbrk(suffix.c_str(), ILLEGAL_CHARS_W))
      ERROR_SET(err, unknown, "Response contains invalid characters");

   *pipe = CreateFile(
      childPipeName.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED,
      nullptr
   );
   if (!pipe->Valid())
      ERROR_SET(err, win32, GetLastError());

   on_client(pipe, err);
   ERROR_CHECK(err);

exit:;
}

void
pollster::windows::CreateLegacyAfUnixClient(
   waiter *w,
   struct sockaddr_un *sun,
   const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
   error *err
)
{
   common::Pointer<waiter> wp = w;
   PWSTR pipeName = nullptr;
   std::wstring pipeNameObj;
   std::shared_ptr<common::FileHandle> mainPipe;
   std::shared_ptr<std::vector<unsigned char>> buffer;

   if (!w)
   {
      pollster::get_common_queue(wp.GetAddressOf(), err);
      ERROR_CHECK(err);

      w = wp.Get();
   }

   pipeName = ConvertPipeName(sun, err);
   ERROR_CHECK(err);

   try
   {
      pipeNameObj = pipeName;
      mainPipe = std::make_shared<common::FileHandle>();
      buffer = std::make_shared<std::vector<unsigned char>>();
      buffer->resize(4096);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   *mainPipe = CreateFile(
      pipeName,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED,
      nullptr
   );
   if (!mainPipe->Valid())
      ERROR_SET(err, win32, GetLastError());

   pollster::windows::ReadFileAsync(
      w,
      mainPipe,
      nullptr,
      buffer->data(),
      buffer->size(),
      std::function<void(error*)>(),
      [wp, buffer, mainPipe, pipeNameObj, on_client] (size_t res, error *err) -> void
      {
         AfUnixClientHello(
            wp,
            buffer->data(),
            res,
            mainPipe,
            pipeNameObj,
            on_client,
            err
         );
      }
   );

exit:
   free(pipeName);
}

static
void
ReadLoop(
   const common::Pointer<pollster::waiter> &w,
   const std::shared_ptr<common::FileHandle> &hClient,
   const std::shared_ptr<std::vector<unsigned char>> &buf,
   const std::function<void(const void *, size_t, error *)> &on_recv,
   const std::function<void(error *)> &on_closed,
   const std::function<void(error *)> &on_error
)
{
   pollster::windows::ReadFileAsync(
      w.Get(),
      hClient,
      nullptr,
      buf->data(),
      buf->size(),
      on_error,
      [w, hClient, buf, on_recv, on_closed, on_error] (DWORD res, error *err) -> void
      {
         if (!res)
         {
            if (on_closed)
            {
               on_closed(err);
               ERROR_CHECK(err);
            }
         }
         else
         {
            on_recv(buf->data(), res, err);
            ERROR_CHECK(err);

            ReadLoop(w, hClient, buf, on_recv, on_closed, on_error);
         }

      exit:
         if (ERROR_FAILED(err) && on_error)
            on_error(err);
      }
   );
}

void
pollster::windows::BindLegacyAfUnixClient(
   waiter *w,
   const std::shared_ptr<common::FileHandle> &hClient,
   StreamSocket::WriteFunction &writeFn,
   const std::function<void(const void *, size_t, error *)> &on_recv,
   const std::function<void(error *)> &on_closed,
   const std::function<void(error *)> &on_error_,
   error *err
)
{
   common::Pointer<waiter> wp = w;
   std::shared_ptr<std::vector<unsigned char>> buf;
   auto on_error = on_error_;

   try
   {
      buf = std::make_shared<std::vector<unsigned char>>();
      buf->resize(4096);

      auto innerError = on_error;
      on_error = [innerError, on_closed] (error *err) -> void
      {
         if (err->source == ERROR_SRC_COM)
         {
            switch (err->code)
            {
            case __HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE):
               error_clear(err);
               if (on_closed)
                  on_closed(err);
               break;
            default:
               ERROR_LOG(err);
               innerError(err);
            }
         }
      };
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   writeFn = [wp, hClient, on_error] (const void *buf, size_t len, const std::function<void(error*)> &onComplete, error *err) -> void
   {
      std::shared_ptr<std::vector<unsigned char>> vec;

      try
      {
         vec = std::make_shared<std::vector<unsigned char>>();
         auto p = (const unsigned char*)buf;
         vec->insert(vec->begin(), p, p+len);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      pollster::windows::WriteFileAsync(
         wp.Get(),
         hClient,
         nullptr,
         vec->data(),
         len,
         on_error,
         [hClient, vec, onComplete] (size_t res, error *err) -> void
         {
            if (onComplete)
               onComplete(err);
         }
      );
   exit:
      if (ERROR_FAILED(err) && on_error)
      {
         on_error(err);
      }
   };

   ReadLoop(wp, hClient, buf, on_recv, on_closed, on_error);
exit:;
}
