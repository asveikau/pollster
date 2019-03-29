/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <pollster/pollster.h>
#include <common/logger.h>
#include <common/thread.h>

#include <mutex>
#include <vector>
#include <stdio.h>

using namespace common;
using namespace pollster;

static void
add_stdin(
   Pointer<waiter> waiter,
   Pointer<auto_reset_signal> stop,
   std::function<void(const void*, size_t, error *)> write_fn,
   error *err
);

int
main(int argc, char **argv)
{
   Pointer<waiter> waiter;
   Pointer<auto_reset_signal> stop;
   std::shared_ptr<pollster::StreamSocket> sock;

   std::function<void(error*)> onError;
   bool gotStop = false;
   error err;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   if (argc < 2)
      ERROR_SET(&err, unknown, "usage: test host port");

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
      sock = std::make_shared<pollster::StreamSocket>(waiter.Get());
      sock->on_connect_progress =
         [] (pollster::ConnectAsyncStatus state, const char *arg, error *err) -> void
         {
            pollster::LogConnectAsyncStatus(state, arg);
         };
      sock->on_error = onError;
      sock->on_closed = [] (error *err) -> void
      {
         log_printf("Connection closed\n");
      };
      sock->on_recv = [] (const void *buf, int len, error *err) -> void
      {
         fwrite(buf, 1, len, stdout);
         fflush(stdout);
      };
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

   add_stdin(
      waiter,
      stop,
      [sock] (const void *buf, size_t n, error *err) -> void
      {
         sock->Write(buf, n);
      },
      &err
   );
   ERROR_CHECK(&err);

   sock->Connect(argv[1], argv[2]);

   while (!gotStop)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}

static void
add_stdin(
   Pointer<waiter> waiter,
   Pointer<auto_reset_signal> stop,
   std::function<void(const void*, size_t, error *)> write_fn,
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
