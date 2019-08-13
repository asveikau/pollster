/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#if defined(_WINDOWS)
#include <pollster/win.h>
#endif

pollster::StreamServer::StreamServer(struct waiter *waiter_)
   : waiter(waiter_)
{
}

pollster::StreamServer::~StreamServer()
{
   for (auto &fd : fds)
   {
      error err;
      fd->remove(&err);
   }
}

void
pollster::StreamServer::AddFd(const std::shared_ptr<common::SocketHandle> &fd, error *err)
{
   common::Pointer<socket_event> sev;
   auto on_client = this->on_client;

   if (listen(fd->Get(), -1))
      ERROR_SET(err, socket);

   set_nonblock(fd->Get(), true, err);
   ERROR_CHECK(err);

   if (!waiter.Get())
   {
      get_common_queue(waiter.GetAddressOf(), err);
      ERROR_CHECK(err);
   }

   try
   {
      auto waiterWeak = waiter.Get();
      waiter->add_socket(
         fd,
         false,
         [waiterWeak, fd, on_client] (socket_event *sev, error *err) -> void
         {
            try
            {
               sev->on_signal = [waiterWeak, fd, on_client] (error *err) -> void
               {
                  common::SocketHandle nfd;
                  std::shared_ptr<StreamSocket> sock;

                  while ((nfd = accept(fd->Get(), nullptr, nullptr)).Valid())
                  {
                     set_nonblock(nfd.Get(), true, err);
                     ERROR_CHECK(err);

                     try
                     {
                        auto nfd2 = std::make_shared<common::SocketHandle>(nfd.Get());
                        nfd.Detach();
                        sock = std::make_shared<StreamSocket>(waiterWeak, nfd2);
                     }
                     catch (std::bad_alloc)
                     {
                        ERROR_SET(err, nomem);
                     }

                     on_client(sock, err);
                     ERROR_CHECK(err);

                     sock->AttachSocket(err);
                     ERROR_CHECK(err);
                  }
               exit:
                  error_clear(err);
               };
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }
         exit:;
         },
         sev.GetAddressOf(),
         err
      );
      ERROR_CHECK(err);

      fds.push_back(sev);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

exit:
   if (ERROR_FAILED(err) && sev.Get())
   {
      error innerErr;

      sev->remove(&innerErr);
   }
}

static void
set_reuse(const std::shared_ptr<common::SocketHandle> &fd, error *err)
{
   int yes = 1;

   if (setsockopt(fd->Get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
      ERROR_SET(err, socket);

#ifdef SO_REUSEPORT
   if (setsockopt(fd->Get(), SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)))
      ERROR_SET(err, socket);
#endif

exit:;
}

static void
NewSocket(std::shared_ptr<common::SocketHandle> &fd, error *err)
{
   pollster::socket_startup(err);
   ERROR_CHECK(err);

   try
   {
      fd = std::make_shared<common::SocketHandle>();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}

void
pollster::StreamServer::AddPort(int port, error *err)
{
   struct sockaddr_in in = {0};
   struct sockaddr_in6 in6 = {0};
   sockaddr *sa = nullptr;
   std::shared_ptr<common::SocketHandle> fd;

   NewSocket(fd, err);
   ERROR_CHECK(err);

   *fd = socket(PF_INET, SOCK_STREAM, 0);
   if (!fd->Valid())
      ERROR_SET(err, socket);

   set_reuse(fd, err);
   ERROR_CHECK(err);

   sockaddr_set_af(&in);
   in.sin_port = htons(port);

   sa = (sockaddr*)&in;

   if (bind(fd->Get(), sa, socklen(sa)))
      ERROR_SET(err, socket);

   AddFd(fd, err);
   ERROR_CHECK(err);

   NewSocket(fd, err);
   ERROR_CHECK(err);

   *fd = socket(PF_INET6, SOCK_STREAM, 0);
   if (!fd->Valid())
      ERROR_SET(err, socket);

   set_reuse(fd, err);
   ERROR_CHECK(err);

   sockaddr_set_af(&in6);
   in6.sin6_port = htons(port);

   sa = (sockaddr*)&in6;

   if (bind(fd->Get(), sa, socklen(sa)))
      ERROR_SET(err, socket);

   AddFd(fd, err);
   ERROR_CHECK(err);

exit:;
}

static void
TryUnlink(const char *path, error *err)
{
   if (!path || !*path)
      return;

#if defined(_WINDOWS)
   auto path16 = ConvertToPwstr(path, err);
   ERROR_CHECK(err);

   if (!DeleteFile(path16))
   {
      auto error = GetLastError();
      switch (error)
      {
      case ERROR_FILE_NOT_FOUND:
         break;
      default:
         ERROR_SET(err, win32, error);
      }
   }

exit:
   free(path16);
#else
   if (unlink(path))
   {
      auto error = errno;
      switch (error)
      {
      case ENOENT:
         break;
      default:
         ERROR_SET(err, errno, error);
      }
   }
exit:;
#endif
}

void
pollster::StreamServer::AddUnixDomain(const char *path, error *err)
{
   struct sockaddr_un un = {0};
   struct sockaddr *sa;
   std::shared_ptr<common::SocketHandle> fd;

   NewSocket(fd, err);
   ERROR_CHECK(err);

   *fd = socket(PF_UNIX, SOCK_STREAM, 0);
   if (!fd->Valid())
   {
#if defined(_WINDOWS)
      goto winFallback;
#endif
      ERROR_SET(err, socket);
   }

   sockaddr_un_set(&un, path, err);
   ERROR_CHECK(err);

   sa = (struct sockaddr*)&un;

   TryUnlink(un.sun_path, err);
   ERROR_CHECK(err);

   if (bind(fd->Get(), sa, socklen(sa)))
   {
#if defined(_WINDOWS)
      if (GetLastError() == WSAEINVAL)
         goto winFallback;
#endif
      ERROR_SET(err, socket);
   }
#if defined(_WINDOWS) && defined(TEST_LEGACY_UNIX_SOCKET)
   goto winFallback;
#endif

   AddFd(fd, err);
   ERROR_CHECK(err);

exit:
   return;
#if defined(_WINDOWS)
winFallback:
   auto on_client = this->on_client;
   auto waiterp = waiter;

   // XXX some old versions of Windows seem to corrupt the sockaddr at bind?
   sockaddr_un_set(&un, path, err);
   ERROR_CHECK(err);

   windows::CreateLegacyAfUnixServer(
      waiter.Get(),
      &un,
      [waiterp, on_client] (const std::shared_ptr<common::FileHandle> &client, error *err) -> void
      {
         try
         {
            auto writeFn = std::make_shared<std::function<void(const void*, int, error *)>>();
            auto writeFnWrapper = [writeFn] (const void *buf, int len, error *err) -> void
            {
               (*writeFn)(buf, len, err);
            };
            auto sock = std::make_shared<StreamSocket>(writeFnWrapper);
            windows::BindLegacyAfUnixClient(
               waiterp.Get(),
               client,
               *writeFn.get(),
               [sock] (const void *buf, int len, error *err) -> void
               {
                  sock->on_recv(buf, len, err);
               },
               [sock] (error *err) -> void
               {
                  sock->on_closed(err);
               },
               [sock] (error *err) -> void
               {
                  sock->on_error(err);
               },
               err
            );
            ERROR_CHECK(err);

            on_client(sock, err);
            ERROR_CHECK(err);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      exit:;
      },
      err
   );
   ERROR_CHECK(err);
#endif
}
