/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/timer.h>
#include <pollster/threads.h>
#include <common/time.h>

pollster::timer::timer()
   : head(nullptr), last_time(0)
{
}

pollster::timer::~timer()
{
   while (head)
   {
      auto p = head;

      *p->prev = p->next;
      p->Release();
   }
}

int64_t
pollster::timer::next_timer(void)
{
   int64_t r = -1;
   if (head)
      r = head->pendingMillis;
   return r;
}

void
pollster::timer::insert(timer_node *r, error *err)
{
   if (thread_helper &&
       !thread_helper->on_owning_thread())
   {
      thread_helper->enqueue_work(
         [this, r] (error *err) -> void
         {
            insert(r, err);
         },
         err
      );

      return;
   }

   r->pendingMillis = r->totalMillis;

   auto prev = &head;

   while ((*prev) && (*prev)->pendingMillis < r->pendingMillis)
   {
      r->pendingMillis -= (*prev)->pendingMillis;
      prev = &((*prev)->next);
   }

   r->prev = prev;
   r->next = *prev;
   if (r->next)
   {
      r->next->prev = &r->next;
      r->next->pendingMillis -= r->pendingMillis;
   }
   *prev = r;
}

void
pollster::timer::add(
   uint64_t millis,
   bool repeating,
   const std::function<void(event*, error*)> &initialize,
   event **ev,
   error *err
)
{
   common::Pointer<timer_node> r;

   *r.GetAddressOf() = new (std::nothrow) timer_node();
   if (!r.Get())
      ERROR_SET(err, nomem);

   if (initialize)
   {
      initialize(r.Get(), err);
      ERROR_CHECK(err);
   }

   r->thread_helper = thread_helper;
   r->repeat = repeating;
   r->totalMillis = millis;

   insert(r.Get(), err);
   ERROR_CHECK(err);
   r->AddRef();
exit:
   if (!ERROR_FAILED(err))
      *ev = r.Detach();
}

void
pollster::timer::begin_poll(error *err)
{
   if (!last_time)
      last_time = get_monotonic_time_millis();
}

void
pollster::timer::end_poll(error *err)
{
   auto start_time = last_time;
   last_time = get_monotonic_time_millis();
   uint64_t ellapsed = last_time - start_time;

   auto prev = &head;

   while ((*prev))
   {
      auto p = *prev;

      if (ellapsed < p->pendingMillis)
      {
         p->pendingMillis -= ellapsed;
         break;
      }

      ellapsed -= p->pendingMillis;
      *prev = p->next;
      if (*prev)
         (*prev)->prev = prev;
      p->prev = nullptr;
      p->next = nullptr;

      p->signal_from_backend(false, err);

      if (ERROR_FAILED(err))
      {
         if (p->on_error)
            p->on_error(err);
         error_clear(err);
         p->repeat = false;
      }

      if (p->repeat)
         insert(p, err);
      else
         p->Release();
   }
}

pollster::timer_node::timer_node()
   : prev(nullptr),
     next(nullptr),
     repeat(false),
     pendingMillis(0),
     totalMillis(0),
     thread_helper(nullptr)
{
}

void
pollster::timer_node::remove(error *err)
{
   if (thread_helper &&
       !thread_helper->on_owning_thread())
   {
      common::Pointer<timer_node> rcThis = this;

      thread_helper->enqueue_work(
         [rcThis] (error *err) -> void
         {
            rcThis->remove(err);
         },
         err
      );

      return;
   }

   if (prev)
   {
      *prev = next;
      if (*prev)
         (*prev)->prev = prev;
      prev = nullptr;
      next = nullptr;
      Release();
   }
}
