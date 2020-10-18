/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/pollster.h>

void
pollster::sigev_extif::remove_sigev(struct sigevent *sigev)
{
   if (!sigev)
      return;
   auto p = (pollster::event*)sigev->sigev_value.sival_ptr;
   if (p)
   {
      sigev->sigev_notify = SIGEV_NONE;
      sigev->sigev_value.sival_ptr = nullptr;
      error err;
      p->remove(&err);
      p->Release();
   }
}

void
pollster::sigev_extif::wrap_sigev(
   struct sigevent *sigev,
   const std::function<void(error *err)> &on_success,
   const std::function<void(error *err)> &on_error,
   error *err
)
{
   common::Pointer<sigev_extif> rc = this;
   common::Pointer<pollster::event> ev;

   add_sigev(
      sigev,
      [&] (pollster::event *ev, error *err) -> void
      {
         ev->on_signal = [ev, sigev, on_success, rc] (error *err) -> void
         {
            auto rc2 = common::Pointer<event>(ev);

            rc->remove_sigev(sigev);

            if (on_success)
               on_success(err);
         };
         ev->on_error = [sigev, on_error, rc] (error *err) -> void
         {
            rc->remove_sigev(sigev);

            if (on_error)
               on_error(err);
         };
      },
      ev.GetAddressOf(),
      err
   );
   ERROR_CHECK(err);
exit:;
}