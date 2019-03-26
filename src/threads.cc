/*
 Copyright (C) 2018, 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/threads.h>

#include <string.h>

pollster::thread_helper::thread_helper()
{
   memset(&owning_thread, 0, sizeof(owning_thread));
   memset(&init, 0, sizeof(init));
}

void
pollster::thread_helper::initialize(thread_helper_init *args, error *err)
{
   thread_get_self(&owning_thread);

   if (!enqueue_work)
   {
      if (!args->queue)
      {
         common::Pointer<auto_reset_signal> ev;

         queue.initialize(err);
         ERROR_CHECK(err);

         args->backend->add_auto_reset_signal(
            true,
            [] (auto_reset_signal *, error *) -> void {},
            ev.GetAddressOf(),
            err
         );

         ev->on_signal = [this] (error *err) -> void
         {
            queue.drain(err);
         };

         queue.on_enqueue = [ev] (error *err) -> void
         {
            ev->signal(err);
         };

         args->queue = &queue;
      }

      auto q = args->queue;
      enqueue_work = [q] (std::function<void(error*)> fn, error *err) -> void
      {
         bool shutdown = false;
         q->enqueue_work(fn, shutdown, err);
      };
   }
exit:;
}

void
pollster::thread_helper::on_exec(thread_helper_init *args, error *err)
{
   struct innerArgs
   {
      thread_helper_init *args;
      thread_helper *p;
   };
   innerArgs args2;
   args2.args = args;
   args2.p = this;
   lazy_init(
      &init,
      [] (void *ctx, error *err) -> void
      {
         auto p = reinterpret_cast<innerArgs*>(ctx);

         p->p->initialize(p->args, err);
      },
      &args2,
      err
   );
}

bool
pollster::thread_helper::on_owning_thread(void)
{
   return thread_is_self(&owning_thread) ||
          !lazy_is_initialized(&init); // XXX: need to close initialization race
}