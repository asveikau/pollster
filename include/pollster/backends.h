/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_backends_h
#define pollster_backends_h

#include "pollster.h"

namespace pollster {

void
create_event_port(waiter **waiter, error *err);

void
create_kqueue(waiter **waiter, error *err);

void
create_epoll(waiter **waiter, error *err);

void
create_dev_poll(waiter **waiter, error *err);

void
create_poll(waiter **waiter, error *err);

void
create_win(waiter **waiter, error *err);

} // end namespace

#endif
