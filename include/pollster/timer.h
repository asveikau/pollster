/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_timer_h_
#define pollster_timer_h_

#include "pollster.h"

namespace pollster {

class thread_helper;

struct timer_node : public event
{
   timer_node **prev, *next;
   bool repeat;
   uint64_t pendingMillis;
   uint64_t totalMillis;
   thread_helper *thread_helper;

   timer_node();

   void remove(error *err);
};

class timer
{
   timer_node *head;
   uint64_t last_time;

   void
   insert(timer_node *n, error *err);

public:

   timer();
   ~timer();

   thread_helper *thread_helper;

   int64_t
   next_timer(void);

   void
   add(
      uint64_t millis,
      bool repeating,
      const std::function<void(event*, error*)> &initialize,
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