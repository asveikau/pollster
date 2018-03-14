#include <wait/wait.h>
#include <common/logger.h>

#include <stdio.h>

using namespace common;

int
main()
{
   Pointer<wait::waiter> waiter;
   error err;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   wait::create(waiter.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   for (;;)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
