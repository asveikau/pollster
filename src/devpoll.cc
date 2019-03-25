/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// This is the backend for the Solaris ~8+ /dev/poll device, which is
// marked deprecated these days in favor of port_create(2).
//

#include <pollster/unix.h>
#include <pollster/backends.h>
#include <common/misc.h>
#include <common/c++/new.h>

#include <sys/devpoll.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <limits.h>

#include <unordered_map>

namespace {

struct dev_poll_backend : public pollster::unix_backend
{
   common::FileHandle pollFd;
   std::unordered_map<int, common::Pointer<pollster::event>> objects;
   struct pollfd *first, *last;

   dev_poll_backend() : first(nullptr), last(nullptr) {}

   void
   initialize(error *err)
   {
      pollFd = open("/dev/poll", O_RDWR);
      if (!pollFd.Valid())
         ERROR_SET(err, errno, errno);
   exit:;
   }

   void
   add_fd(int fd, bool write, pollster::event *object, error *err)
   {
      struct pollfd pfd = {0};
      pfd.fd = fd;
      pfd.events = POLLIN | (write ? POLLOUT : 0) | POLLPRI;

      try
      {
         objects[fd] = common::Pointer<pollster::event>(object);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      if (::write(pollFd.Get(), &pfd, sizeof(pfd)) != sizeof(pfd))
         ERROR_SET(err, errno, errno);

   exit:
      if (ERROR_FAILED(err))
         objects.erase(fd);
   }

   void
   remove_fd(int fd, pollster::event *object, error *err)
   {
      struct pollfd pfd = {0};
      auto i = objects.find(fd);

      if (i == objects.end())
         ERROR_SET(err, unknown, "fd not found");

      pfd.fd = fd;
      pfd.events = POLLREMOVE;

      if (write(pollFd.Get(), &pfd, sizeof(pfd)) != sizeof(pfd))
         ERROR_SET(err, errno, errno);

      objects.erase(i);

      if (first)
      {
         auto src = first;
         auto dst = first;
         int nRemoved = 0;

         while (src < last)
         {
            if (src->fd == fd)
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
      struct pollfd pfd[2] = {{0}};
      pfd[0].fd = fd;
      pfd[0].events = POLLREMOVE;
      pfd[1].fd = fd;
      pfd[1].events = POLLIN | (write ? POLLOUT : 0) | POLLPRI;

      if (::write(pollFd.Get(), &pfd, sizeof(pfd)) != sizeof(pfd))
         ERROR_SET(err, errno, errno);
   exit:;
   }

   void
   exec(error *err)
   {
      auto timeoutInt = timer.next_timer();
      struct dvpoll dp = {0};
      struct pollfd pollfds[256];
      int n = 0;

      if (!objects.size() && timeoutInt < 0)
         ERROR_SET(err, unknown, "exec() called with empty fd set");

      base_exec(err);
      ERROR_CHECK(err);

      if (timeoutInt >= 0)
      {
         if (timeoutInt > INT_MAX)
            timeoutInt = INT_MAX;

         timer.begin_poll(err);
         ERROR_CHECK(err);
      }

      dp.dp_timeout = timeoutInt;
      dp.dp_nfds = ARRAY_SIZE(pollfds);
      dp.dp_fds = pollfds;

      n = ioctl(pollFd.Get(), DP_POLL, &dp);
      if (n < 0)
         ERROR_SET(err, errno, errno);

      if (timeoutInt >= 0)
      {
         timer.end_poll(err);
         ERROR_CHECK(err);
      }

      for (first = pollfds, last = pollfds + n; first < last; )
      {
         auto p = first++;
         if (p->revents)
         {
            auto i = objects.find(p->fd);
            if (i != objects.end())
            {
               i->second->signal_from_backend(err);
               ERROR_CHECK(err);
            }
         }
      }
      first = last = nullptr;
   exit:;
   }

};

} // end namespace

void
pollster::create_dev_poll(waiter **waiter, error *err)
{
   common::Pointer<dev_poll_backend> r;

   common::New(r.GetAddressOf(), err);
   ERROR_CHECK(err);

   r->initialize(err);
   ERROR_CHECK(err);

exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}
