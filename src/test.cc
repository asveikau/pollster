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

static void
add_socket(
   Pointer<waiter> waiter,
   std::shared_ptr<common::SocketHandle> fd,
   Pointer<auto_reset_signal> stop,
   error *err
)
{
   Pointer<socket_event> socket;
   auto writeBuffer = std::make_shared<std::vector<char>>();
   std::function<void(const void*, size_t, error *)> write_fn;

   waiter->add_socket(
      fd,
      false,
      [fd, writeBuffer] (socket_event *socket, error *err) -> void
      {
         socket->on_signal = [fd, socket, writeBuffer] (error *err) -> void
         {
            char buf[4096];
            int r;

      #if defined(_WINDOWS)
            {std::lock_guard<std::mutex> lock(io_lock);
      #endif
            while (writeBuffer->size() && (r = send(fd->Get(), writeBuffer->data(), writeBuffer->size(), 0)) > 0)
            {
               writeBuffer->erase(writeBuffer->begin(), writeBuffer->begin() + r);
               if (!writeBuffer->size())
               {
                  socket->set_needs_write(false, err);
                  ERROR_CHECK(err);
               }
            }
      #if defined(_WINDOWS)
            } // end lock guard
      #endif

            while ((r = recv(fd->Get(), buf, sizeof(buf), 0)) > 0)
            {
               fwrite(buf, 1, r, stdout);
               fflush(stdout);
            }
         exit:;
         };
      },
      socket.GetAddressOf(),
      err
   );
   ERROR_CHECK(err);

   write_fn = [socket, writeBuffer] (const void *buf, size_t len, error *err) -> void
   {
#if defined(_WINDOWS)
      std::lock_guard<std::mutex> lock(io_lock);
#endif
      bool was_empty = !writeBuffer->size();

      try
      {
         writeBuffer->insert(writeBuffer->end(), (const char*)buf, (const char*)buf+len);
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

   add_stdin(waiter, stop, write_fn, err);
   ERROR_CHECK(err);
exit:;
}

int
main(int argc, char **argv)
{
   Pointer<waiter> waiter;
   Pointer<auto_reset_signal> stop;
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

   socket_startup(&err);
   ERROR_CHECK(&err);

   onError = [stop] (error *err) -> void
   {
      error_clear(err);
      stop->signal(err);
   };

   pollster::ConnectAsync(
      waiter.Get(),
      argv[1],
      argv[2],
      [] (pollster::ConnectAsyncStatus state, const char *arg, error *err) -> void {},
      [waiter, stop] (const std::shared_ptr<common::SocketHandle> &fd, error *err) -> void
      {
         add_socket(waiter, fd, stop, err);
         ERROR_CHECK(err);
      exit:;
      },
      onError
   );

   while (!gotStop)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
