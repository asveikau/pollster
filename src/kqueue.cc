#include <pollster/unix.h>
#include <pollster/backends.h>
#include <common/misc.h>
#include <common/c++/new.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <unistd.h>

#include <vector>
#include <map>

namespace {

struct kqueue_backend : public pollster::unix_backend
{
   int kq;
   std::vector<struct kevent> changelist;
   struct kevent *cursor, *last;
   std::map<intptr_t, common::Pointer<pollster::event>> refCounts;

   kqueue_backend() : kq(-1), cursor(nullptr), last(nullptr) {}
   ~kqueue_backend() { if (kq >= 0) close(kq);}

   void
   initialize(error *err)
   {
      kq = kqueue();
      if (kq < 0)
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
         if (p.udata == obj)
            return &p;
      }

      struct kevent *r = nullptr;
      int n = obj->writeable ? 2 : 1;

      try
      {
         changelist.resize(changelist.size() + n);
      }
      catch (std::bad_alloc)
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
      EV_SET(&ev[0], fd, EVFILT_READ, cmd, 0, 0, object);
      if (object->writeable)
      {
         if (cmd != EV_DELETE)
            cmd |= (write ? EV_ENABLE : EV_DISABLE);

         EV_SET(&ev[1], fd, EVFILT_WRITE, cmd, 0, 0, object);
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
         catch (std::bad_alloc)
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
      auto ev = allocate(object, err);
      ERROR_CHECK(err);

      setup_kevent(ev, fd, EV_DELETE, false, object);

      remove_pending(object);

      refCounts.erase((intptr_t)object);
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
         if (ev->udata != object)
            *dst++ = *ev;
      }
      this->last = dst;
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
      struct kevent events[256];
      int nevents = 0;
      struct timespec timeoutStorage;
      struct timespec *timeout = nullptr;
      auto timeoutInt = timer.next_timer();

      base_exec(err);
      ERROR_CHECK(err);

      if (timeoutInt >= 0)
      {
         timeout = &timeoutStorage;
         timeout->tv_sec = timeoutInt / 1000;
         timeout->tv_nsec = (timeoutInt % 1000) * 1000000;

         timer.begin_poll(err);
         ERROR_CHECK(err);
      }

      nevents = kevent(
         kq,
         changelist.size() ? changelist.data() : nullptr,
         changelist.size(),
         events,
         ARRAY_SIZE(events),
         timeout
      );

      changelist.resize(0);      

      if (timeoutInt >= 0)
      {
         timer.end_poll(err);
         ERROR_CHECK(err);
      }

      for (cursor = events, last = events + nevents;
           cursor < last;
           cursor++)
      {
         process(cursor, err);
         ERROR_CHECK(err);
      }
   exit:;
   }

   void
   process(struct kevent *ev, error *err)
   {
      auto obj = (pollster::event*)ev->udata;

      obj->signal_from_backend(err);
   }
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
