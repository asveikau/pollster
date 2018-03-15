#ifndef pollster_win_h_
#define pollster_win_h_

#include "pollster.h"
#include "timer.h"

namespace pollster {

struct win_backend : public waiter
{
   timer timer;

   void
   add(HANDLE handle, event *object, error *err);

   void
   add_socket(
      SOCKET fd,
      bool write,
      socket_event **ev,
      error *err
   );

   void
   add_auto_reset_signal(
      bool repeating,
      auto_reset_signal **ev,
      error *err
   );

   void
   add_timer(
      uint64_t millis,
      bool repeating,
      event **ev,
      error *err
   );

   void
   exec(error *err);
};

} // end namespace


#endif