/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_threads_h_
#define pollster_threads_h_

#include <common/thread.h>
#include <common/lazy.h>

#include "pollster.h"
#include "messagequeue.h"

namespace pollster {

struct thread_helper_init
{
   waiter *backend;
   message_queue *queue;

   thread_helper_init() : backend(nullptr), queue(nullptr)
   {}
};

class thread_helper
{
   thread_id owning_thread;
   lazy_init_state init;
   message_queue queue;

   void
   initialize(thread_helper_init *args, error *err);

public:

   thread_helper();

   void
   on_exec(thread_helper_init *args, error *err);

   bool
   on_owning_thread(void);

   std::function<void(std::function<void(error*)>, error *)>
   enqueue_work;
};

} // end namespace

#endif