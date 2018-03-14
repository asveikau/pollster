#ifndef pollster_timer_h_
#define pollster_timer_h_

#include "pollster.h"

namespace pollster {

struct timer_node : public event
{
   timer_node **prev, *next;
   bool repeat;
   uint64_t pendingMillis;
   uint64_t totalMillis;

   timer_node();

   void remove(error *err);
};

class timer
{
   timer_node *head;
   uint64_t last_time;

   void
   insert(timer_node *n);

public:

   timer();
   ~timer();

   int64_t
   next_timer(void);

   void
   add(
      uint64_t millis,
      bool repeating,
      event **ev,
      error *err
   );

   void
   begin_poll(error *err);

   void
   end_poll(error *err);
};

} // end namespace

#endif