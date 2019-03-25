/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// This is the backend for the Solaris 10+.
//

#include <pollster/unix.h>
#include <pollster/backends.h>
#include <common/misc.h>
#include <common/c++/new.h>

#include <port.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <limits.h>

#include <unordered_map>
#include <memory>

namespace {

struct event_port_backend : public pollster::unix_backend
{
   std::shared_ptr<common::FileHandle> port;
   std::unordered_map<int, common::Pointer<pollster::event>> objects;
   port_event_t *first, *last;
   int currentFd;

   event_port_backend() : first(nullptr), last(nullptr), currentFd(-1) {}

   void
   initialize(error *err)
   {
      try
      {
         port = std::make_shared<common::FileHandle>();
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
      *port = port_create();
      if (!port->Valid())
         ERROR_SET(err, errno, errno);
   exit:;
   }

   void
   add_fd(int fd, bool write, pollster::event *object, error *err)
   {
      int events = POLLIN | (write ? POLLOUT : 0) | POLLPRI;
      try
      {
         objects[fd] = common::Pointer<pollster::event>(object);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
      if (port_associate(port->Get(), PORT_SOURCE_FD, fd, events, object))
         ERROR_SET(err, errno, errno);
      object->writeable = write;
   exit:
      if (ERROR_FAILED(err))
         objects.erase(fd);
   }

   void
   remove_fd(int fd, pollster::event *object, error *err)
   {
      if (fd == currentFd)
         currentFd = -1;
      else if (port_dissociate(port->Get(), PORT_SOURCE_FD, fd))
         ERROR_SET(err, errno, errno);

      objects.erase(fd);

      if (first)
      {
         auto src = first;
         auto dst = first;
         int nRemoved = 0;

         while (src < last)
         {
            if (src->portev_source == PORT_SOURCE_FD && src->portev_object == fd)
            {
               ++nRemoved;
               ++src;
            }
            else
            {
               *dst++ = *src++;
            }
         }

         last -= nRemoved;
      }
   exit:;
   }

   void
   set_write(int fd, bool write, pollster::event *object, error *err)
   {
      if (fd != currentFd)
      {
         int events = POLLIN | (write ? POLLOUT : 0) | POLLPRI;

         if (port_dissociate(port->Get(), PORT_SOURCE_FD, fd) && errno != ENOENT)
            ERROR_SET(err, errno, errno);
         if (port_associate(port->Get(), PORT_SOURCE_FD, fd, events, object))
            ERROR_SET(err, errno, errno);
      }

      object->writeable = write;
   exit:;
   }

   void
   exec(error *err)
   {
      auto timeoutInt = timer.next_timer();
      port_event_t events[256];
      struct timespec ts = {0};
      struct timespec *tsp = nullptr;
      uint_t n = 0;

      if (!objects.size() && timeoutInt < 0)
         ERROR_SET(err, unknown, "exec() called with empty fd set");

      base_exec(err);
      ERROR_CHECK(err);

      if (timeoutInt >= 0)
      {
         if (timeoutInt > INT_MAX)
            timeoutInt = INT_MAX;

         ts.tv_sec = timeoutInt / 1000;
         ts.tv_nsec = (timeoutInt % 1000) * 1000;
         tsp = &ts;

         timer.begin_poll(err);
         ERROR_CHECK(err);
      }

      // API is a tad confusing.  This means: return when at least 1 event is present.
      // Higher values means more blocking until that number of events is in the queue.
      //
      n = 1;

      if (port_getn(port->Get(), events, ARRAY_SIZE(events), &n, tsp))
      {
         switch (errno)
         {
         case ETIME:
            n = 0;
            break;
         default:
            ERROR_SET(err, errno, errno);
         }
      }

      if (timeoutInt >= 0)
      {
         timer.end_poll(err);
         ERROR_CHECK(err);
      }

      for (first = events, last = events + n; first < last; )
      {
         auto p = first++;
         auto obj = (pollster::event*)p->portev_user;
         common::Pointer<pollster::event> q;

         if (p->portev_source == PORT_SOURCE_FD)
         {
            currentFd = p->portev_object;
            q = obj;
         }

         obj->signal_from_backend(err);
         ERROR_CHECK(err);

         if (currentFd >= 0)
         {
            int events = POLLIN | (q->writeable ? POLLOUT : 0) | POLLPRI;
            if (port_associate(port->Get(), PORT_SOURCE_FD, currentFd, events, obj))
            {
               error innerErr;
               error_set_errno(&innerErr, errno);
               if (q->on_error)
                  q->on_error(&innerErr);
               error_clear(&innerErr);
               q->remove(&innerErr);
            }
            currentFd = -1;
         }
      }
      first = last = nullptr;
   exit:;
   }

};

} // end namespace

void
pollster::create_event_port(waiter **waiter, error *err)
{
   common::Pointer<event_port_backend> r;

   common::New(r.GetAddressOf(), err);
   ERROR_CHECK(err);

   r->initialize(err);
   ERROR_CHECK(err);

exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}
