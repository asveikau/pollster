/*
 Copyright (C) 2018, 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <pollster/pollster.h>
#include <common/logger.h>
#include <common/thread.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <vector>
#include <stdio.h>

using namespace common;
using namespace pollster;

static void
add_stdin(
   Pointer<waiter> waiter,
   Pointer<auto_reset_signal> stop,
   const std::function<void(const void*, size_t, error *)> &write_fn,
   error *err
);

static void
add_socket(
   const std::shared_ptr<pollster::StreamSocket> &sock,
   pollster::SslArgs *ssl,
   const std::function<void(error *)> &onError,
   error *err
);

std::vector<std::shared_ptr<pollster::StreamSocket>>
sockets;

static void
usage()
{
   fprintf(stderr, "usage: test [-tcpclient host port] [-tcpserver port] "
#if defined(HAVE_SSL)
                               "[-tlsclient host port] "
#endif
                               "[-unixclient path] [-unixserver path] "
                   "\n");
   exit(1);
}

int
main(int argc, char **argv)
{
   Pointer<waiter> waiter;
   Pointer<auto_reset_signal> stop;
   std::vector<std::function<void(error *)>> ops;

   std::function<void(error*)> onError;
   bool gotStop = false;
   error err;

   bool needUsage = true;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   create(waiter.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   pollster::set_common_queue(waiter.Get());

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

   onError = [stop] (error *err) -> void
   {
      error_clear(err);
      stop->signal(err);
   };

   try
   {
      for (int i = 1; i<argc; ++i)
      {
         pollster::SslArgs *ssl = nullptr;
         pollster::SslArgs sslStorage;

         if (!strcmp(argv[i], "-tcpclient") ||
             (ssl = !strcmp(argv[i], "-tlsclient") ? &sslStorage : nullptr))
         {
            if (i+2 >= argc)
               usage();

            needUsage = false;

            const char *host = argv[++i];
            const char *port = argv[++i];

            if (ssl)
            {
               ssl->HostName = host;

               ssl->Callbacks.OnCipherKnown = [] (const char *cipher, error *err) -> void
               {
                  log_printf("Cipher: %s", cipher);
               };
            }

            auto sock = std::make_shared<pollster::StreamSocket>();
            add_socket(sock, ssl, onError, &err);
            ERROR_CHECK(&err);

            ops.push_back(
               [sock, host, port] (error *err) -> void
               {
                  sock->Connect(host, port);
               }
            );
         }
         if (!strcmp(argv[i], "-unixclient"))
         {
            if (i+1 >= argc)
               usage();

            needUsage = false;

            const char *path = argv[++i];
            auto sock = std::make_shared<pollster::StreamSocket>();
            add_socket(sock, ssl, onError, &err);
            ERROR_CHECK(&err);

            ops.push_back(
               [sock, path] (error *err) -> void
               {
                  sock->ConnectUnixDomain(path);
               }
            );
         }
         else if (!strcmp(argv[i], "-tcpserver") || !strcmp(argv[i], "-unixserver"))
         {
            if (i+1 >= argc)
               usage();

            needUsage = false;

            const char *portString = argv[++i];
            static pollster::StreamServer server;

            if (!server.on_client)
            {
               server.on_client = [onError] (
                  const std::shared_ptr<pollster::StreamSocket> &fd,
                  error *err
               ) -> void
               {
                  log_printf("server: got client\n");

                  add_socket(fd, nullptr, onError, err);
               };
            }

            if (!strcmp(argv[i], "-tcpserver"))
               server.AddPort(atoi(portString), &err);
            else
               server.AddUnixDomain(portString, &err);
            ERROR_CHECK(&err);
         }
      }
   }
   catch (const std::bad_alloc&)
   {
      ERROR_SET(&err, nomem);
   }


   if (needUsage)
      usage();

   add_stdin(
      waiter,
      stop,
      [] (const void *buf, size_t n, error *err) -> void
      {
         for (auto &sock : sockets)
         {
            sock->Write(buf, n);
         }
      },
      &err
   );
   ERROR_CHECK(&err);

   for (auto &op : ops)
   {
      op(&err);
      ERROR_CHECK(&err);
   }

   ops.clear();

   while (!gotStop)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}

static void
add_socket(
   const std::shared_ptr<pollster::StreamSocket> &sock,
   pollster::SslArgs *ssl,
   const std::function<void(error *)> &onError,
   error *err
)
{
   if (ssl)
   {
#if !defined(HAVE_SSL)
      ERROR_SET(err, unknown, "TLS not supported by library");
#else
      pollster::CreateSslFilter(*ssl, sock->filter, err);
      ERROR_CHECK(err);
      sock->CheckFilter(err);
      ERROR_CHECK(err);
#endif
   }
   try
   {
      auto sockWeak = sock.get();

      sock->on_connect_progress =
         [] (pollster::ConnectAsyncStatus state, const char *arg, error *err) -> void
         {
            pollster::LogConnectAsyncStatus(state, arg);
         };
      sock->on_error = onError;
      sock->on_closed = [sockWeak] (error *err) -> void
      {
         log_printf("Connection closed\n");

         sockets.erase(
            std::remove_if(
               sockets.begin(),
               sockets.end(),
               [sockWeak] (const std::shared_ptr<pollster::StreamSocket> &fd) -> bool
               {
                  return fd.get() == sockWeak;
               }
            ),
            sockets.end()
         );
      };
      sock->on_recv = [] (const void *buf, size_t len, error *err) -> void
      {
         fwrite(buf, 1, len, stdout);
         fflush(stdout);
      };
      sockets.push_back(sock);
   }
   catch (const std::bad_alloc&)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}

static void
add_stdin(
   Pointer<waiter> waiter,
   Pointer<auto_reset_signal> stop,
   const std::function<void(const void*, size_t, error *)> &write_fn,
   error *err
)
{
   Pointer<socket_event> stdinEv;

#if !defined(_WINDOWS)
   waiter->add_socket(
      std::make_shared<common::FileHandle>(0),
      false,
      [stop, write_fn] (socket_event *stdinEv, error *err) -> void
      {
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
      },
      stdinEv.GetAddressOf(),
      err
   );
   ERROR_CHECK(err);
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
         err
      );
      ERROR_CHECK(err);
      detach_thread(&id);
   }
#endif
exit:;
}
