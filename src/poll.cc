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

#include <poll.h>
#include <limits.h>

#include <vector>
#include <algorithm>

namespace {

struct poll_backend : public pollster::unix_backend
{
   std::vector<struct pollfd> pollfds;
   std::vector<common::Pointer<pollster::event>> objects;
   int cursor;

   poll_backend() : cursor(0) {}

   int
   find_fd(int fd)
   {
      for (int i=0; i<pollfds.size(); ++i)
         if (pollfds[i].fd == fd)
            return i;

      return -1;
   }

   void swap(int i, int j)
   {
      if (i == j)
         return;
      std::swap(pollfds[i], pollfds[j]);
      std::swap(objects[i], objects[j]);
   }

   void
   add_fd(int fd, bool write, pollster::event *object, error *err)
   {
      struct pollfd pfd = {0};
      pfd.fd = fd;
      pfd.events = POLLIN | (write ? POLLOUT : 0) | POLLPRI;

      pollfds.push_back(pfd);
      objects.push_back(common::Pointer<pollster::event>(object));
   }

   void
   remove_fd(int fd, pollster::event *object, error *err)
   {
      int idx = find_fd(fd);
      if (idx >= 0)
      {
         if (idx == pollfds.size() - 1)
         {
            goto resize;
         }
         else if (idx < cursor)
         {
            for (int j = cursor+1; j<pollfds.size(); ++j)
            {
               if (!pollfds[j].revents)
               {
                  swap(idx, j);
                  goto resize;
               }
            }

            --cursor;

            while (idx < pollfds.size() - 1)
            {
               pollfds[idx] = std::move(pollfds[idx+1]);
               objects[idx] = std::move(objects[idx+1]);
               ++idx;
            }

            goto resize;
         }
         else
         {
            swap(idx, pollfds.size() - 1);
         resize:
            pollfds.resize(pollfds.size() - 1);
            objects[pollfds.size()] = nullptr;
            objects.resize(pollfds.size());
         }
      }
   }

   void
   set_write(int fd, bool write_flag, pollster::event *object, error *err)
   {
      int idx = find_fd(fd);
      if (idx >= 0)
      {
         auto &p = pollfds[idx].events;
         if (write_flag)
            p |= POLLOUT;
         else
            p &= ~POLLOUT;
      }
   }

   void
   exec(error *err)
   {
      auto timeoutInt = timer.next_timer();
      int n = 0;

      if (!pollfds.size() && timeoutInt < 0)
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

      n = poll(pollfds.data(), pollfds.size(), timeoutInt); 
      if (n < 0)
         ERROR_SET(err, errno, errno);

      if (timeoutInt >= 0)
      {
         timer.end_poll(err);
         ERROR_CHECK(err);
      }

      for (cursor = 0; n && cursor < pollfds.size(); ++cursor)
      {
         if (pollfds[cursor].revents)
         {
            --n;
            pollfds[cursor].revents = 0;
            objects[cursor]->signal_from_backend(err);
            ERROR_CHECK(err);
         }
      }
      cursor = 0;
   exit:;
   }
};

} // end namespace

void
pollster::create_poll(waiter **waiter, error *err)
{
   common::Pointer<poll_backend> r;

   common::New(r.GetAddressOf(), err);
   ERROR_CHECK(err);

exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}
