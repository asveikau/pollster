/*
 Copyright (C) 2018, 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_pollster_h
#define pollster_pollster_h

#include <common/c++/refcount.h>
#include <common/c++/handle.h>
#include <common/error.h>

#include <functional>
#include <memory>

#if !defined(_WINDOWS)
#include <signal.h>
#endif

namespace pollster
{

// XXX
#if defined (_WINDOWS)
struct win_backend;
#endif

// Basic event, i.e. signallable object such as a file descriptor.
//
struct event : virtual public common::RefCountable
{
   // Remove the event from its owning FD set.
   //
   virtual void remove(error *err) = 0;

   // Some subclasses will set to true to indicate that it's possible
   // to signal this FD for write-readiness.
   //
   bool writeable;

   // Filled by caller.  Will be called when FD is signalled/ready.
   //
   std::function<void(error*)> on_signal;

protected:
   // Internal version of on_signal().  Some backends and object types
   // will call the public "on_signal", and then clear some backend state
   // on the FD (eg. on Unix, draining a pipe on auto-reset events so they
   // won't remain signalled on the next iteration.)
   //
   std::function<void(error*)> on_signal_impl;

   // XXX
#if defined (_WINDOWS)
   friend struct ::pollster::win_backend;
#endif
public:

   // Called when there is an error processing this descriptor.
   // If this gets called, your fd is about to be removed from the wait list.
   //
   std::function<void(error*)> on_error;

   // Purposeful break of abstraction.  May not return anything useful.
   //
#if defined (_WINDOWS)
   typedef HANDLE handle_t;
#else
   typedef int handle_t;
#endif
   virtual handle_t get_handle() const { return (handle_t) -1; }

   //
   // The following should be called within a backend's exec() implementation.
   //

   void
   signal_from_backend(error *err)
   {
      signal_from_backend(true, err);
   }

   void
   signal_from_backend(bool check_error, error *err)
   {
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
         error_clear(err);
      }
   }

   event() : writeable(false) {}
};

// Similar to Win32 events or Linux eventfd:
// An object that can be either signalled or unsignalled, and will
// return to the unsignalled state after being processed within the 
// wait backend.
//
struct auto_reset_signal : virtual public event
{
   // Causes on_signal() to be called from waiter::exec().
   //
   virtual void signal(error *err) = 0;
};

// Wraps a socket.
//
struct socket_event : virtual public event
{
   // Set to true to indicate we want to be woken for write-readiness,
   // false otherwise.
   //
   virtual void set_needs_write(bool b, error *err) = 0;
};

// Used to specify an API for extended_interface.
//
enum extended_interface
{
   Signal,
   SigEvent,
   ImmediateClose,
};

// Pure virtual base class for poll backend.
//
struct waiter : public virtual common::RefCountable
{
   // Add a socket to the fd set.
   // @write:      Set to true if we currently want to poll for write availability.
   // @initialize: Your earliest opportunity to set ->on_error and ->on_signal.
   //              If you put this off until later, it's theoretically possible
   //              for the fd to be signalled and processed on another thread.
   //              Setting handlers early lets us close that race condition.
   // @ev:         Out parameter that receives the backend FD object.
   //
   virtual void
   add_socket(
      const std::shared_ptr<common::SocketHandle> &fd,
      bool write,
      const std::function<void(socket_event *, error *)> &initialize,
      socket_event **ev,
      error *err
   ) = 0;

   // Add an auto-reset event to the fd set.
   // @repeating:  Object stays in the wait backend after being signalled.
   //              Otherwise it is removed after processing.
   // @initialize: See comment at add_socket.
   // @ev:         Out parameter that receives the backend FD object.
   //
   virtual void
   add_auto_reset_signal(
      bool repeating,
      const std::function<void(auto_reset_signal *, error *)> &initialize,
      auto_reset_signal **ev,
      error *err
   ) = 0;

   // The "initialize" race condition is less critical for auto_reset_signal,
   // since it doesn't end up signalled from something handling elsewhere.
   // Provide a simpler override for that case.
   //
   inline void
   add_auto_reset_signal(
      bool repeating,
      auto_reset_signal **ev,
      error *err
   )
   {
      add_auto_reset_signal(
         repeating,
         std::function<void(auto_reset_signal*, error*)>(),
         ev,
         err
      );
   }

   // Add an event that will be signalled after a delay.
   // @millis:     Delay in milliseconds
   // @repeating:  Object stays in the wait backend after being signalled.
   //              Otherwise it is removed after processing.
   // @initialize: See comment at add_socket.
   // @ev:         Out parameter that receives the backend FD object.
   //
   virtual void
   add_timer(
      uint64_t millis,
      bool repeating,
      const std::function<void(event *, error *)> &initialize,
      event **ev,
      error *err
   ) = 0;

   // Runs an iteration of the event loop.
   // Careful about bouncing around in threads here!  Generally
   // should be called from the same thread repeatedly.
   //
   virtual void
   exec(error *err) = 0;

   // Attempt to get a more platform-specific interface.
   //
   virtual void *
   get_interface(extended_interface ifspec, error *err)
   {
      return nullptr;
   }
};

struct signal_extif : public virtual common::RefCountable
{
   virtual void
   add_signal(
      int sig,
      const std::function<void(event *, error *)> &initialize,
      event **ev,
      error *err
   ) = 0;
};

struct sigev_extif : public virtual common::RefCountable
{
   virtual void
   add_sigev(
      struct sigevent *sigev,
      const std::function<void(event *, error *)> &initialize,
      event **ev,
      error *err
   ) = 0;

   virtual void
   remove_sigev(struct sigevent *sigev);

   void
   wrap_sigev(
      struct sigevent *sigev,
      const std::function<void(error *err)> &on_success,
      const std::function<void(error *err)> &on_error,
      error *err
   );
};

struct immediate_close_extif : public virtual common::RefCountable
{
   virtual void
   notify_immediate_close(event *object, error *err) = 0;
};

// Create a backend object.
//
void
create(
   waiter **waiter,
   error *err
);

// Get a pooled worker thread, i.e. lazy-initialized global backend
// instance.
//
void
get_common_queue(
   waiter **waiter,
   error *err
);

// If your application happens to have a worker thread already, you can
// set it to be the global one.  Do this early, as it will be a no-op if
// get_common_queue was already called.
//
void
set_common_queue(
   waiter *w
);

// Helper function for timers.
//
void
sleep(
   waiter *w,
   uint64_t millis,
   const std::function<void(error*)> &fn,
   error *err
);

static inline
void
sleep(uint64_t millis, const std::function<void(error *)> &fn, error *err)
{
   sleep(nullptr, millis, fn, err);
}

void
ReadFileAsync(
   waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const uint64_t *offset_opt,
   void *buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
);

void
WriteFileAsync(
   waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const uint64_t *offset_opt,
   const void *buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
);

} // end namespace

#endif
