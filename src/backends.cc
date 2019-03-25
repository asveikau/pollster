/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/backends.h>

struct backend_factory
{
   void (*fn)(pollster::waiter **, error *err);
};

void
pollster::create(waiter **w, error *err)
{
   static const backend_factory backends[] =
   {
#if defined(USE_KQUEUE)
      {create_kqueue},
#endif
#if defined(USE_EPOLL)
      {create_epoll},
#endif
#if defined(USE_DEV_POLL)
      {create_dev_poll},
#endif
#if defined(USE_POLL)
      {create_poll},
#endif
#if defined(_WINDOWS)
      {create_win},
#endif
      {nullptr}
   };
   *w = nullptr;
   for (auto f = backends; f->fn; ++f)
   {
      f->fn(w, err);
      if (ERROR_FAILED(err))
         error_clear(err);
      else
         break;
   }
   if (!*w)
      ERROR_SET(err, unknown, "could not create backend object");
exit:;
}
