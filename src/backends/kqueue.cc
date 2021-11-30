/*
 Copyright (C) 2018, 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/unix.h>
#include <pollster/backends.h>
#include <common/misc.h>
#include <common/c++/new.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <unistd.h>

#include <algorithm>
#include <vector>
#include <map>

#if defined(__NetBSD__)
#define UDATA_OBJ_CAST(X) ((intptr_t)(X))
#else
#define UDATA_OBJ_CAST(X) (X)
#endif

#if defined(SIGEV_KEVENT)
#define USE_SIGEV
#endif

namespace {

struct kqueue_backend :
   public pollster::unix_backend
   , public pollster::signal_extif
#if defined(USE_SIGEV)
   , public pollster::sigev_extif
#endif
   , public pollster::immediate_close_extif
{
   common::FileHandle kq;
   std::vector<struct kevent> changelist;
   struct kevent *cursor, *last;
   std::map<intptr_t, common::Pointer<pollster::event>> refCounts;
   std::vector<common::Pointer<pollster::event>> toDelete;

   kqueue_backend() : cursor(nullptr), last(nullptr) {}

   void
   initialize(error *err)
   {
      kq = kqueue();
      if (!kq.Valid())
         ERROR_SET(err, errno, errno);
   exit:;
   }

   struct kevent *
   allocate(pollster::event *obj, error *err)
   {
      // Something already pending for this object?
      // Return it back.
      //
      for (auto &p : changelist)
      {
         if (p.udata == UDATA_OBJ_CAST(obj))
            return &p;
      }

      struct kevent *r = nullptr;
      int n = obj->writeable ? 2 : 1;

      try
      {
         changelist.resize(changelist.size() + n);
      }
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }

      r = changelist.data() + changelist.size() - n;
   exit:
      return r;
   }

   void
   setup_kevent(
      struct kevent *ev,
      int fd,
      int cmd,
      bool write,
      pollster::event *object
   )
   {
      EV_SET(&ev[0], fd, EVFILT_READ, cmd, 0, 0, UDATA_OBJ_CAST(object));
      if (object->writeable)
      {
         if (cmd != EV_DELETE)
            cmd |= (write ? EV_ENABLE : EV_DISABLE);

         EV_SET(&ev[1], fd, EVFILT_WRITE, cmd, 0, 0, UDATA_OBJ_CAST(object));
      }
   }

   void
   add_fd(int fd, bool write, pollster::event *object, bool ref, error *err)
   {
      struct kevent *ev = nullptr;

      if (ref)
      {
         try
         {
            refCounts[(intptr_t)object] = common::Pointer<pollster::event>(object);
         }
         catch (const std::bad_alloc&)
         {
            ERROR_SET(err, nomem);
         }
      }

      ev = allocate(object, err);
      ERROR_CHECK(err);

      setup_kevent(ev, fd, EV_ADD, write, object);
   exit:
      if (ERROR_FAILED(err) && ref)
      {
         refCounts.erase((intptr_t)object);
      }
   }

   void
   remove_fd(int fd, pollster::event *object, error *err)
   {
      auto it = refCounts.find((intptr_t)object);
      struct kevent *ev = nullptr;

      if (it == refCounts.end())
         goto exit;

      ev = allocate(object, err);
      ERROR_CHECK(err);

      setup_kevent(ev, fd, EV_DELETE, false, object);

      remove_pending(object);

      try
      {
         toDelete.push_back(common::Pointer<pollster::event>(object));
      }
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }

      refCounts.erase(it);
   exit:;
   }

   void
   remove_pending(pollster::event *object)
   {
      struct kevent *ev, *dst;

      // Remove any pending events with this fd in our user
      // mode kevent buffer.
      //
      for (ev = dst = cursor+1; ev < last; ++ev)
      {
         if (ev->udata != UDATA_OBJ_CAST(object))
            *dst++ = *ev;
      }
      last = dst;
   }

   void
   notify_immediate_close(pollster::event *object, error *err)
   {
      for (auto i = changelist.size(); i != 0; i--)
      {
         auto ev = &changelist[i-1];
         if (ev->udata == UDATA_OBJ_CAST(object))
            changelist.erase(changelist.begin()+(i-1));
      }
   }

   void
   add_fd(int fd, bool write_flag, pollster::event *object, error *err)
   {
      add_fd(fd, write_flag, object, true, err);
   }

   void
   set_write(int fd, bool write_flag, pollster::event *object, error *err)
   {
      add_fd(fd, write_flag, object, false, err);
   }

   void
   exec(error *err)
   {
      struct kevent events[EVENT_BUFSZ];
      int nevents = 0;
      struct timespec timeoutStorage;
      struct timespec *timeout = nullptr;
      auto timeoutInt = timer.next_timer();
      bool fastDelete = false;

      if (!refCounts.size() && timeoutInt < 0)
         ERROR_SET(err, unknown, "exec() called with empty fd set");

      base_exec(err);
      ERROR_CHECK(err);

      if (toDelete.size())
      {
         timeout = &timeoutStorage;
         timeout->tv_sec = 0;
         timeout->tv_nsec = 0;
         fastDelete = true;
      }
      else if (timeoutInt >= 0)
      {
         timeout = &timeoutStorage;
         timeout->tv_sec = timeoutInt / 1000;
         timeout->tv_nsec = (timeoutInt % 1000) * 1000000;

         timer.begin_poll(err);
         ERROR_CHECK(err);
      }

      nevents = kevent(
         kq.Get(),
         changelist.size() ? changelist.data() : nullptr,
         changelist.size(),
         events,
         ARRAY_SIZE(events),
         timeout
      );

      changelist.resize(0);
      toDelete.resize(0);

      cursor = events - 1;
      last = events + nevents;

      if (timeoutInt >= 0 && !fastDelete)
      {
         timer.end_poll(err);
         ERROR_CHECK(err);
      }

      for (cursor++; cursor < last; cursor++)
      {
         process(cursor, err);
         ERROR_CHECK(err);
      }
   exit:
      cursor = last = nullptr;
   }

   void
   process(struct kevent *ev, error *err)
   {
      auto obj = (pollster::event*)ev->udata;

      if ((ev->flags & EV_ERROR))
      {
         auto it = refCounts.find((uintptr_t)obj);
         ERROR_SET(err, errno, ev->data);
      exit:
         if (it != refCounts.end())
         {
            common::Pointer<pollster::event> rc = obj;

            refCounts.erase(it);

            if (obj->on_error)
               obj->on_error(err);
         }
         error_clear(err);
         return;
      }

      obj->signal_from_backend(err);
   }

   virtual void *
   get_interface(pollster::extended_interface ifspec, error *err)
   {
      switch (ifspec)
      {
      case pollster::Signal:
         AddRef();
         return static_cast<pollster::signal_extif*>(this);
#if defined(USE_SIGEV)
      case pollster::SigEvent:
         AddRef();
         return static_cast<pollster::sigev_extif*>(this);
#endif
      case pollster::ImmediateClose:
         AddRef();
         return static_cast<pollster::immediate_close_extif*>(this);
      default:
         break;
      }
      return unix_backend::get_interface(ifspec, err);
   }

   struct event_base : public pollster::event
   {
      kqueue_backend *p;   

   protected:
      template <typename RemoveFn, typename CompleteFn>
      void
      remove_base(
         RemoveFn removeFn,
         CompleteFn completeFn,
         error *err
      )
      {
         auto q = p;
         p = nullptr;
         if (q)
         {
            auto rc = common::Pointer<pollster::event>(this);

            removeFn(q, err);
            ERROR_CHECK(err);

            q->remove_pending(this);

            q->refCounts.erase((uintptr_t)this);

            completeFn(q, err);
            ERROR_CHECK(err);
         }
      exit:;
      }
   };

   struct sig_event : public event_base
   {
      int sig;

      void
      remove(error *err)
      {
         remove_base(
            [this] (kqueue_backend *q, error *err) -> void
            {
               auto kevent = q->allocate(this, err);
               ERROR_CHECK(err);

               EV_SET(kevent, sig, EVFILT_SIGNAL, EV_DELETE, 0, 0, UDATA_OBJ_CAST(this));
            exit:;
            },
            [this] (kqueue_backend *q, error *err) -> void
            {
               signal(sig, SIG_DFL);
            },
            err
         );
      }
   };

   void
   add_signal(
      int sig,
      const std::function<void(pollster::event *, error *)> &initialize,
      pollster::event **ev,
      error *err
   )
   {
      struct kevent *kevent = nullptr;
      common::Pointer<sig_event> evp;
      bool ref = false;

      common::New(evp, err);
      ERROR_CHECK(err);

      evp->p = this;
      evp->sig = sig;

      try
      {
         refCounts[(intptr_t)evp.Get()] = common::Pointer<pollster::event>(evp.Get());
      }
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }

      ref = true;

      initialize(evp.Get(), err);
      ERROR_CHECK(err);

      kevent = allocate(evp.Get(), err);
      ERROR_CHECK(err);

      EV_SET(kevent, sig, EVFILT_SIGNAL, EV_ADD|EV_ENABLE, 0, 0, UDATA_OBJ_CAST(evp.Get()));
      *ev = evp.Detach();

      signal(sig, SIG_IGN);
   exit:
      if (ERROR_FAILED(err) && ref)
         refCounts.erase((uintptr_t)evp.Get());
   }

#if defined(USE_SIGEV)

   struct sigev_event : public event_base
   {
      void
      remove(error *err)
      {
         remove_base(
            [] (kqueue_backend *q, error *err) -> void {},
            [] (kqueue_backend *q, error *err) -> void {},
            err
         );
      }
   };

   void
   add_sigev(
      struct ::sigevent *sigev,
      const std::function<void(pollster::event *, error *)> &initialize,
      pollster::event **ev,
      error *err
   )
   {
      common::Pointer<sigev_event> evp;
      bool ref = false;

      common::New(evp, err);
      ERROR_CHECK(err);

      evp->p = this;

      try
      {
         refCounts[(intptr_t)evp.Get()] = common::Pointer<pollster::event>(evp.Get());
      }
      catch (const std::bad_alloc&)
      {
         ERROR_SET(err, nomem);
      }

      ref = true;

      initialize(evp.Get(), err);
      ERROR_CHECK(err);

      memset(sigev, 0, sizeof(*sigev));

      sigev->sigev_notify = SIGEV_KEVENT;
      sigev->sigev_notify_kqueue = kq.Get();
      sigev->sigev_value.sival_ptr = evp.Get();

      evp->AddRef();
      *ev = evp.Detach();
   exit:
      if (ERROR_FAILED(err) && ref)
         refCounts.erase((uintptr_t)evp.Get());
   }
#endif
};

} // end namespace

void
pollster::create_kqueue(waiter **waiter, error *err)
{
   common::Pointer<kqueue_backend> r;

   common::New(r.GetAddressOf(), err);
   ERROR_CHECK(err);

   r->initialize(err);
   ERROR_CHECK(err);
exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}
