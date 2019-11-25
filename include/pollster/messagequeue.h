/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_messagequeue_h_
#define pollster_messagequeue_h_

#include <common/error.h>
#include <common/mutex.h>
#include <vector>
#include <functional>

namespace pollster {

class message_queue
{
   bool init;
   mutex lock;
   std::vector<std::function<void(error*)>> queue;
public:

   message_queue();
   message_queue(const message_queue &) = delete;
   ~message_queue();

   std::function<void(error *err)> on_enqueue;

   void
   initialize(error *err);

   void
   synchronize(const std::function<void(void)> &op);

   bool
   enqueue_work(const std::function<void(error*)> &func, bool &shutdown, error *err);

   void
   drain(error *err);

   bool
   is_empty();
};

} // end namespace

#endif
