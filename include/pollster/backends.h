#ifndef pollster_backends_h
#define pollster_backends_h

#include "pollster.h"

namespace pollster {

void
create_kqueue(waiter **waiter, error *err);

void
create_poll(waiter **waiter, error *err);

void
create_win(waiter **waiter, error *err);

} // end namespace

#endif
