/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <common/lazy.h>
#include <common/sem.h>
#include <common/thread.h>
#include <pollster/pollster.h>

static void
init_queue(void *contextp, error *err)
{
   auto context = reinterpret_cast<pollster::waiter**>(contextp);
   common::Pointer<pollster::waiter> waiter;
   common::Pointer<pollster::auto_reset_signal> event;
   semaphore sem = {0};
   thread_id id = {0};

   sm_init(&sem, 0, err);
   ERROR_CHECK(err);

   pollster::create(waiter.GetAddressOf(), err);
   ERROR_CHECK(err);

   // Create a signalled handle to run the first ->exec().
   // This first ->exec() will have the side effect of setting thread affinity.
   //
   waiter->add_auto_reset_signal(false, event.GetAddressOf(), err);
   ERROR_CHECK(err);
   event->signal(err);
   ERROR_CHECK(err);

   common::create_thread(
      [waiter, &sem] (void) -> void
      {
         error err;

         // Set thread affinity and wake up parent.
         //
         waiter->exec(&err);
         sm_post(&sem);

         // "Real" event loop.
         //
         while (!ERROR_FAILED(&err))
         {
            waiter->exec(&err);
         }
      },
      &id,
      err
   );
   ERROR_CHECK(err);

   detach_thread(&id);

   sm_wait(&sem);

exit:
   if (!ERROR_FAILED(err))
      *context = waiter.Detach();
   sm_destroy(&sem);
}

static lazy_init_state lazy = {0};
static pollster::waiter *common_waiter = nullptr;

void
pollster::get_common_queue(
   pollster::waiter **waiter,
   error *err
)
{
   lazy_init(&lazy, init_queue, &common_waiter, err);
   ERROR_CHECK(err);

exit:
   *waiter = common_waiter;
   (*waiter)->AddRef();
}

void
pollster::set_common_queue(
   waiter *w
)
{
   error err;
   struct state
   {
      waiter **target;
      waiter *w;
   };
   state st = {&common_waiter, w};
   lazy_init(
      &lazy,
      [] (void *ctx, error *err) -> void
      {
         state &st = *(state*)ctx;
         *st.target = st.w;
         st.w->AddRef();
      },
      &st,
      &err
   );
}
