#ifndef pollster_unix_h_
#define pollster_unix_h_

#include "pollster.h"
#include "timer.h"
#include "threads.h"

namespace pollster {

struct unix_backend : public waiter
{
   timer timer;
   thread_helper thread_helper;

   unix_backend();

   virtual void
   add_fd(int fd, bool write_flag, event *object, error *err) = 0;

   virtual void
   set_write(int fd, bool write_flag, event *object, error *err) = 0;

   virtual void
   remove_fd(int fd, event *object, error *err) = 0;

   void
   base_add_fd(int fd, bool write_flag, event *object, error *err);

   void
   base_exec(error *err);

   void
   add_socket(
      int fd,
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
};

} // end namespace

#endif
