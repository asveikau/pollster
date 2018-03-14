#ifndef wait_unix_h_
#define wait_unix_h_

#include "wait.h"

namespace wait {

struct unix_backend : public waiter
{   
   virtual void
   add_fd(int fd, bool write_flag, event *object, error *err) = 0;

   virtual void
   set_write(int fd, bool write_flag, event *object, error *err) = 0;

   virtual void
   remove_fd(int fd, event *object, error *err) = 0;

   int64_t get_timeout(void);

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
