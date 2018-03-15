#include <pollster/socket.h>
#include <pollster/pollster.h>
#include <common/logger.h>

#include <vector>
#include <stdio.h>

using namespace common;
using namespace pollster;

static int
create_socket(const char *host, const char *service, error *err)
{
   struct addrinfo hint = {0};
   struct addrinfo *addrs = nullptr;
   int r = 0;
   SOCKET fd = INVALID_SOCKET;

   hint.ai_socktype = SOCK_STREAM;

   r = getaddrinfo(host, service, &hint, &addrs);
   if (r)
      ERROR_SET(err, unknown, gai_strerror(r));

   fd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
   if (fd == INVALID_SOCKET)
      ERROR_SET(err, socket);

   if (connect(fd, addrs->ai_addr, addrs->ai_addrlen))
      ERROR_SET(err, socket);

   set_nonblock(fd, true, err);
   ERROR_CHECK(err);

exit:
   if (addrs) freeaddrinfo(addrs);
   if (ERROR_FAILED(err) && fd >= 0)
   {
      closesocket(fd);
      fd = INVALID_SOCKET;
   }
   return fd;
}

int
main(int argc, char **argv)
{
   Pointer<waiter> waiter;
   Pointer<auto_reset_signal> stop;
   Pointer<socket_event> stdinEv;
   Pointer<socket_event> socket;
   socket_event *socketWeak = nullptr;
   std::vector<char> writeBuffer;
   std::function<void(const void*, size_t, error *)> write_fn;
   bool gotStop = false;
   SOCKET fd =INVALID_SOCKET;
   error err;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   if (argc < 2)
      ERROR_SET(&err, unknown, "usage: test host port");

   create(waiter.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   fd = create_socket(argv[1], argv[2], &err);
   ERROR_CHECK(&err);

   waiter->add_socket(
      fd,
      false,
      socket.GetAddressOf(),
      &err
   );
   ERROR_CHECK(&err);

   socketWeak = socket.Get();
   socket->on_signal = [fd, socketWeak, &writeBuffer] (error *err) -> void
   {
#define exit innerExit
      char buf[4096];
      int r;

      while (writeBuffer.size() && (r = write(fd, writeBuffer.data(), writeBuffer.size())) > 0)
      {
         writeBuffer.erase(writeBuffer.begin(), writeBuffer.begin() + r);
         if (!writeBuffer.size())
         {
            socketWeak->set_needs_write(false, err);
            ERROR_CHECK(err);
         }
      }

      while ((r = read(fd, buf, sizeof(buf))) > 0)
      {
         fwrite(buf, 1, r, stdout);
         fflush(stdout);
      }
   exit:;
#undef exit
   };

   write_fn = [socket, &writeBuffer] (const void *buf, size_t len, error *err) -> void
   {
#define exit innerExit
      bool was_empty = !writeBuffer.size();

      try
      {
         writeBuffer.insert(writeBuffer.end(), (const char*)buf, (const char*)buf+len);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      if (was_empty)
      {
         socket->set_needs_write(true, err);
         ERROR_CHECK(err);
      }
   exit:;
#undef exit
   };

   waiter->add_auto_reset_signal(
      false,
      stop.GetAddressOf(),
      &err
   );
   ERROR_CHECK(&err);

   stop->on_signal = [&gotStop] (error *err) -> void
   {
      gotStop = true;
   };

   waiter->add_socket(
      0,
      false,
      stdinEv.GetAddressOf(),
      &err
   );
   ERROR_CHECK(&err);

   stdinEv->on_signal = [stop, write_fn] (error *err) -> void
   {
#define exit innerExit
      char buf[4096];
      int r;

      while ((r = read(0, buf, sizeof(buf))) > 0)
      {
         write_fn(buf, r, err);
         ERROR_CHECK(err);

         r = -1;
         errno = EAGAIN;
         break;
      }

      if (!r)
         stop->signal(err);
      else
      {
         switch(errno)
         {
         case EAGAIN:
         case EINTR:
            break;
         default:
            ERROR_SET(err, errno, errno);
         }
      }
   exit:;
#undef exit
   };

   while (!gotStop)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
