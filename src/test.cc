/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/pollster.h>
#include <common/logger.h>
#include <common/thread.h>

#include <mutex>
#include <vector>
#include <stdio.h>

using namespace common;
using namespace pollster;

#if defined(_WINDOWS)
static
std::mutex io_lock;
#endif

static int
create_socket(const char *host, const char *service, error *err)
{
   struct addrinfo hint = {0};
   struct addrinfo *addrs = nullptr;
   int r = 0;
   SOCKET fd = INVALID_SOCKET;

   hint.ai_socktype = SOCK_STREAM;

   socket_startup(err);
   ERROR_CHECK(err);

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
      char buf[4096];
      int r;

#if defined(_WINDOWS)
      {std::lock_guard<std::mutex> lock(io_lock);
#endif
      while (writeBuffer.size() && (r = send(fd, writeBuffer.data(), writeBuffer.size(), 0)) > 0)
      {
         writeBuffer.erase(writeBuffer.begin(), writeBuffer.begin() + r);
         if (!writeBuffer.size())
         {
            socketWeak->set_needs_write(false, err);
            ERROR_CHECK(err);
         }
      }
#if defined(_WINDOWS)
      } // end lock guard
#endif

      while ((r = recv(fd, buf, sizeof(buf), 0)) > 0)
      {
         fwrite(buf, 1, r, stdout);
         fflush(stdout);
      }
   exit:;
   };

   write_fn = [socket, &writeBuffer] (const void *buf, size_t len, error *err) -> void
   {
#if defined(_WINDOWS)
      std::lock_guard<std::mutex> lock(io_lock);
#endif
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

#if !defined(_WINDOWS)
   waiter->add_socket(
      0,
      false,
      stdinEv.GetAddressOf(),
      &err
   );
   ERROR_CHECK(&err);

   stdinEv->on_signal = [stop, write_fn] (error *err) -> void
   {
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
   };
#else
   {
      thread_id id;
      common::create_thread(
         [write_fn, stop] (void) -> void
         {
            HANDLE stdIn = GetStdHandle(STD_INPUT_HANDLE);
            char buf[4096];
            DWORD out;
            CONSOLE_READCONSOLE_CONTROL ctrl = {0};
            error err;

            SetConsoleCP(CP_UTF8);

            ctrl.nLength = sizeof(ctrl);
            #define CTRL_X(UPPER) (1 + ((UPPER) - 'A'))
            ctrl.dwCtrlWakeupMask = (1UL << CTRL_X('D')) | (1UL << CTRL_X('Z'));

            while (ReadConsoleA(stdIn, buf, sizeof(buf), &out, &ctrl) && out)
            {
               bool eof = false;

               for (int i=0; i<out; ++i)
               {
                  if (buf[i] == CTRL_X('D') || buf[i] == CTRL_X('Z'))
                  {
                     out = i;
                     eof = true;
                  }
               }

               write_fn(buf, out, &err);
               ERROR_CHECK(&err);

               if (eof)
                  break;
            }
            #undef CTRL_X
         exit:
            error_clear(&err);
            stop->signal(&err);
         },
         &id,
         &err
      );
      ERROR_CHECK(&err);
      detach_thread(&id);
   }
#endif

   while (!gotStop)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
