/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// Filter interface for sockapi.
// Useful eg. for implementing SSL/TLS.
//

#ifndef pollster_filter_h_
#define pollster_filter_h_

#include <common/error.h>
#include <functional>
#include <stddef.h>

namespace pollster
{

struct FilterEvents
{
   FilterEvents() {}
   FilterEvents(const FilterEvents &) = delete;
   virtual ~FilterEvents() {}

   virtual void
   OnAsyncError(error *err) {}

   virtual void
   OnBytesToWrite(const void *buf, size_t len, const std::function<void(error*)> &onComplete) = 0;

   virtual void
   OnBytesReceived(const void *buf, size_t len, error *err) = 0;

   virtual void
   OnClosed(error *err) = 0;
};

struct Filter
{
   Filter() {}
   Filter(const Filter &) = delete;
   virtual ~Filter() {}

   virtual void
   Write(const void *buf, size_t len, const std::function<void(error*)> &onComplete) = 0;

   virtual void
   CloseNotify(error *err) {}

   virtual void
   OnBytesReceived(const void *buf, size_t len, error *err) = 0;
   
   virtual void
   OnEof() {}

   std::shared_ptr<FilterEvents> Events;

   virtual void
   OnEventsInitialized(error *err) {}
};

} // end namespace

#endif
