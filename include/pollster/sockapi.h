/*
 Copyright (C) 2018-2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_sockapi_h_
#define pollster_sockapi_h_

#include <common/c++/handle.h>
#include <common/c++/refcount.h>

#include <pollster/pollster.h>

#include <functional>
#include <memory>
#include <vector>
#include <mutex>

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

void
ConnectAsync(
   pollster::waiter *waiter, // can be nullptr for default
   const char *host,
   const char *service,
   std::function<void(ConnectAsyncStatus, const char *, error *)> onProgress,
   std::function<void(const std::shared_ptr<common::SocketHandle> &, error *)> onResult,
   std::function<void(error *)> onError
);

class StreamSocket
{
   common::Pointer<waiter> waiter;
   std::shared_ptr<common::SocketHandle> fd;
   common::Pointer<socket_event> sev;
   std::vector<char> writeBuffer;
   std::mutex writeLock;
public:
   StreamSocket(
      struct waiter *waiter_ = nullptr,
      std::shared_ptr<common::SocketHandle> fd_ = std::make_shared<common::SocketHandle>()
   )
   : waiter(waiter_), fd(fd_) 
   {
   }
   StreamSocket(const StreamSocket &) = delete;

   std::function<void(ConnectAsyncStatus, const char *, error *)> on_connect_progress;
   std::function<void(error *)> on_error;
   std::function<void(const void *, int, error *)> on_recv;
   std::function<void(error *)> on_closed;

   void
   Connect(const char *host, const char *service);

   void
   Write(const void *buf, int len);

private:
   void
   AttachSocket(error *err);
};

} // end namespace

#endif
