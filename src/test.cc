#include <pollster/pollster.h>
#include <common/logger.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

using namespace common;
using namespace pollster;

int
main()
{
   Pointer<waiter> waiter;
   Pointer<auto_reset_signal> stop;
   Pointer<socket_event> stdinEv;
   bool gotStop = false;
   error err;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

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

   waiter->add_socket(
      0,
      false,
      stdinEv.GetAddressOf(),
      &err
   );
   ERROR_CHECK(&err);

   stdinEv->on_signal = [stop] (error *err) -> void
   {
      char buf[4096];
      int r;

      while ((r = read(0, buf, sizeof(buf))) > 0)
      {
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

   while (!gotStop)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
