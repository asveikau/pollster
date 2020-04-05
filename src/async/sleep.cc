/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/pollster.h>

void
pollster::sleep(
   waiter *w,
   uint64_t millis,
   const std::function<void(error*)> &fn,
   error *err
)
{
   common::Pointer<waiter> wp;
   common::Pointer<event> ev;

   if (!w)
   {
      get_common_queue(wp.GetAddressOf(), err);
      ERROR_CHECK(err);
      w = wp.Get();
   }

   w->add_timer(
      millis,
      false,
      [&fn] (event *ev, error *err) -> void
      {
         ev->on_signal = fn;
      },
      ev.GetAddressOf(),
      err
   );
   ERROR_CHECK(err);

exit:;
}
