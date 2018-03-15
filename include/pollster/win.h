#ifndef pollster_win_h_
#define pollster_win_h_

#include "pollster.h"
#include "timer.h"

namespace pollster {

class wait_loop
{
   common::Pointer<event> objects[MAXIMUM_WAIT_OBJECTS];
   HANDLE handles[MAXIMUM_WAIT_OBJECTS];
   int nHandles;

   int
   find_handle(HANDLE h);

public:
   wait_loop(bool is_slave=false);
   wait_loop(const wait_loop&) = delete;
   ~wait_loop();

   int
   slots_available(void);

   void
   add_handle(HANDLE h, event *object, error *err);

   void
   remove_handle(HANDLE h);

   void
   exec(timer *optional_timer, error *err);
};

struct win_backend : public waiter
{
   timer timer;
   wait_loop wait_loop;

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
