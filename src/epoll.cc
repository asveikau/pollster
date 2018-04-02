#include <pollster/unix.h>
#include <pollster/backends.h>
#include <common/misc.h>

#include <sys/epoll.h>
#include <unistd.h>
#include <limits.h>

#include <vector>
#include <map>

namespace {

struct epoll_backend : public pollster::unix_backend
{
   int pfd;
   std::map<intptr_t, common::Pointer<pollster::event>> refCounts;
   struct epoll_event *cursor, *last;

   epoll_backend() : pfd(-1), cursor(nullptr), last(nullptr) {}
   ~epoll_backend() { if (pfd >= 0) close(pfd); }

   void
   initialize(error *err)
   {
      pfd = epoll_create1(0);
      if (pfd < 0)
         ERROR_SET(err, errno, errno);
   exit:;
   }

   void
   setup_event(
      struct epoll_event *ev,
      int fd,
      bool write,
      pollster::event *object
   )
   {
      ev->events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLET;
      if (write)
         ev->events |= EPOLLOUT;
      ev->data.ptr = object;
   }

   void
   add_fd(int fd, bool write, pollster::event *object, error *err)
   {
      struct epoll_event ev;

      try
      {
         refCounts[(intptr_t)object] = common::Pointer<pollster::event>(object);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      setup_event(&ev, fd, write, object);
      if (epoll_ctl(pfd, EPOLL_CTL_ADD, fd, &ev))
         ERROR_SET(err, errno, errno);

   exit:
      if (ERROR_FAILED(err))
         refCounts.erase((intptr_t)object);
   }

   void
   remove_fd(int fd, pollster::event *object, error *err)
   {
      struct epoll_event ev;

      setup_event(&ev, fd, false, object);
      if (epoll_ctl(pfd, EPOLL_CTL_DEL, fd, &ev))
         ERROR_SET(err, errno, errno);

      remove_pending(object);

      refCounts.erase((intptr_t)object);
   exit:;
   }

   void
   remove_pending(pollster::event *object)
   {
      struct epoll_event *ev, *dst;

      // Remove any pending events with this fd in our user
      // mode event buffer.
      //
      for (ev = dst = cursor+1; ev < last; ++ev)
      {
         if (ev->data.ptr != object)
            *dst++ = *ev;
      }
      this->last = dst;
   }

   void
   set_write(int fd, bool write, pollster::event *object, error *err)
   {
      struct epoll_event ev;

      setup_event(&ev, fd, write, object);
      if (epoll_ctl(pfd, EPOLL_CTL_MOD, fd, &ev))
         ERROR_SET(err, errno, errno);

   exit:;
   }

   void
   exec(error *err)
   {
      struct epoll_event events[256];
      int nevents = 0;
      auto timeoutInt = timer.next_timer();
      int timeout = -1;

      if (timeoutInt >= 0)
      {
         timeout = (int)(MIN(INT_MAX, timeoutInt));

         timer.begin_poll(err);
         ERROR_CHECK(err);
      }

      nevents = epoll_wait(pfd, events, ARRAY_SIZE(events), timeout);

      if (nevents < 0)
         ERROR_SET(err, errno, errno);

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
   process(struct epoll_event *ev, error *err)
   {
      auto obj = (pollster::event*)ev->data.ptr;

      obj->signal_from_backend(err);
   }
};

} // end namespace

void
pollster::create_epoll(waiter **waiter, error *err)
{
   common::Pointer<epoll_backend> r;

   try
   {
      *r.GetAddressOf() = new epoll_backend();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   r->initialize(err);
   ERROR_CHECK(err);
exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}