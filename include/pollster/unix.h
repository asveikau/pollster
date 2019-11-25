/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

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
      const std::shared_ptr<common::SocketHandle> &fd,
      bool write,
      const std::function<void(socket_event *, error *)> &initialize,
      socket_event **ev,
      error *err
   );

   void
   add_auto_reset_signal(
      bool repeating,
      const std::function<void(auto_reset_signal *, error *)> &initialize,
      auto_reset_signal **ev,
      error *err
   );

   void
   add_timer(
      uint64_t millis,
      bool repeating,
      const std::function<void(event *, error *)> &initialize,
      event **ev,
      error *err
   );
};

} // end namespace

#endif
