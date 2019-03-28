#include <pollster/socket.h>
#include <pollster/sockapi.h>

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
                  std::shared_ptr<common::SocketHandle> nfd2;
                  std::shared_ptr<StreamSocket> sock;

                  while ((nfd = accept(fd->Get(), nullptr, nullptr)).Valid())
                  {
                     set_nonblock(nfd.Get(), true, err);
                     ERROR_CHECK(err);

                     try
                     {
                        nfd2 = std::make_shared<common::SocketHandle>(nfd.Get());
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

void
pollster::StreamServer::AddPort(int port, error *err)
{
   struct sockaddr_in in = {0};
   struct sockaddr_in6 in6 = {0};
   std::shared_ptr<common::SocketHandle> fd;

   auto newSock = [&fd] (error *err) -> void
   {
      try
      {
         fd = std::make_shared<common::SocketHandle>();
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   };

   newSock(err);
   ERROR_CHECK(err);

   *fd = socket(PF_INET, SOCK_STREAM, 0);
   if (!fd->Valid())
      ERROR_SET(err, socket);

   in.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
   in.sin_len = sizeof(in);
#endif
   in.sin_port = htons(port);

   if (bind(fd->Get(), (sockaddr*)&in, sizeof(in)))
      ERROR_SET(err, socket);

   AddFd(fd, err);
   ERROR_CHECK(err);

   *fd = socket(PF_INET6, SOCK_STREAM, 0);
   if (!fd->Valid())
      ERROR_SET(err, socket);

   in6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
   in6.sin6_len = sizeof(in6);
#endif
   in6.sin6_port = htons(port);

   if (bind(fd->Get(), (sockaddr*)&in6, sizeof(in6)))
      ERROR_SET(err, socket);

   AddFd(fd, err);
   ERROR_CHECK(err);

exit:;
}