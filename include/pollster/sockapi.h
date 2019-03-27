/*
 Copyright (C) 2018-2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_sockapi_h_
#define pollster_sockapi_h_

#include <common/c++/handle.h>

#include <functional>
#include <memory>

namespace pollster
{

void
GetAddrInfoAsync(
   const char *host,
   const char *service,
   struct addrinfo *hint,
   std::function<void(const std::shared_ptr<struct addrinfo> &, error *)> onResult,
   std::function<void(error *)> onError
);

enum ConnectAsyncStatus
{
   HostLookup,
   Connect,
   Connected,
};

void
LogConnectAsyncStatus(ConnectAsyncStatus status, const char *arg);

struct waiter;

void
ConnectAsync(
   pollster::waiter *waiter, // can be nullptr for default
   const char *host,
   const char *service,
   std::function<void(ConnectAsyncStatus, const char *, error *)> onProgress,
   std::function<void(const std::shared_ptr<common::SocketHandle> &, error *)> onResult,
   std::function<void(error *)> onError
);

} // end namespace

#endif
