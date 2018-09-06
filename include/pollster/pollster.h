#ifndef pollster_pollster_h
#define pollster_pollster_h

#include <common/c++/refcount.h>
#include <common/error.h>

#include <functional>

#if !defined(_MSC_VER) && !defined(SOCKET_defined_)
typedef int SOCKET;
#define SOCKET_defined_
#endif

namespace pollster
{

struct event : virtual public common::RefCountable
{
   virtual void remove(error *err) = 0;

   bool writeable;

   std::function<void(error*)> on_signal;
   std::function<void(error*)> on_signal_impl;

   std::function<void(error*)> on_error;

   void
   signal_from_backend(error *err)
   {
      signal_from_backend(true, err);
   }

   void
   signal_from_backend(bool check_error, error *err)
   {
      common::Pointer<event> rc = this;

      if (on_signal_impl)
         on_signal_impl(err);
      else if (on_signal)
         on_signal(err);

      if (check_error && ERROR_FAILED(err))
      {
         if (on_error)
            on_error(err);

         error_clear(err);
         remove(err);
      }
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
   virtual void detach() = 0;
};

struct waiter : public common::RefCountable
{
   virtual void
   add_socket(
      SOCKET fd,
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

void
get_common_queue(
   waiter **waiter,
   error *err
);

} // end namespace

#endif
