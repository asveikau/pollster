/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/messagequeue.h>
#include <common/c++/lock.h>

pollster::message_queue::message_queue() : init(false)
{
}

void
pollster::message_queue::initialize(error *err)
{
   mutex_init(&lock, err);
   ERROR_CHECK(err);
   init = true;
exit:;
}

pollster::message_queue::~message_queue()
{
   if (init)
      mutex_destroy(&lock);
}

void
pollster::message_queue::synchronize(std::function<void(void)> op)
{
   common::locker l;

   l.acquire(lock);
   op();
}

void
pollster::message_queue::drain(error *err)
{
   std::vector<std::function<void(error*)>> queueDrain;
   common::locker l;

   l.acquire(lock);
   std::swap(queueDrain, queue);
   l.release();

   for (auto &fn : queueDrain)
   {
      fn(err);
      ERROR_CHECK(err);
   }
exit:;
}

bool
pollster::message_queue::enqueue_work(std::function<void(error*)> func, bool &shutdown, error *err)
{
   common::locker l;
   bool r = false;

   l.acquire(lock);
   auto wasEmpty = !queue.size();
   if (shutdown)
      goto exit;
   try
   {
      queue.push_back(func);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
   if (wasEmpty && on_enqueue)
      on_enqueue(err);
   r = true;
exit:
   return r;
}

bool
pollster::message_queue::is_empty()
{
   return !queue.size();
}