#ifndef wait_wait_h
#define wait_wait_h

#include <common/c++/refcount.h>
#include <common/error.h>

#include <functional>

namespace wait
{

struct event : virtual public common::RefCountable
{
   virtual void remove(error *err) = 0;

   bool writeable;

   std::function<void(error*)> on_signal;
   std::function<void(error*)> on_signal_impl;

   void
   invoke_from_backend(error *err)
   {
      if (on_signal_impl)
         on_signal_impl(err);
      else if (on_signal)
         on_signal(err);
   }

   event() : writeable(false) {}
};

struct auto_reset_signal : virtual public event
{
   virtual void signal(error *err) = 0;
};

struct socket_event : virtual public event
{
   virtual void set_needs_write(bool b, error *err) = 0;
};

struct waiter : public common::RefCountable
{
   virtual void
   add_socket(
      int fd,
      bool write,
      socket_event **ev,
      error *err
   ) = 0;

   virtual void
   add_auto_reset_signal(
      bool repeating,
      auto_reset_signal **ev,
      error *err
   ) = 0;

   virtual void
   add_timer(
      uint64_t millis,
      bool repeating,
      event **ev,
      error *err
   ) = 0;

   virtual void
   exec(error *err) = 0;
};

void
create(
   waiter **waiter,
   error *err
);

} // end namespace

#endif
