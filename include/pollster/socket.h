/*
 Copyright (C) 2018-2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_socket_h_
#define pollster_socket_h_

#include <functional>

#if defined(_WINDOWS)

#pragma comment(lib, "ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>

#include <stdbool.h>

#include <common/error.h>
#include <common/misc.h>

#undef gai_strerror
#define gai_strerror gai_strerrorA

static INLINE
void
error_set_socket(error *err)
{
   error_set_win32(err, GetLastError());
}

static INLINE
void
set_nonblock(SOCKET fd, bool on, error *err)
{
   unsigned long onl = on ? 1L : 0L;
   if (ioctlsocket(fd, FIONBIO, &onl))
      ERROR_SET(err, socket);
exit:;
}

static INLINE
void
socket_startup(error *err)
{
   WSADATA data = {0};
   if (WSAStartup(MAKEWORD(2,2), &data))
      ERROR_SET(err, win32, GetLastError());
exit:;
}

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include <common/error.h>
#include <common/misc.h>

static INLINE
void
error_set_socket(error *err)
{
   error_set_errno(err, errno);
}

static INLINE
void
set_nonblock(int fd, bool on, error *err)
{
   if (fcntl(fd, F_SETFL, O_NONBLOCK, on ? 1 : 0))
      ERROR_SET(err, errno, errno);
exit:;
}

#define socket_startup(...) ((void)0)

#endif

#include <common/c++/handle.h>

namespace pollster
{

void
error_set_gai(error *err, int r);

void
GetAddrInfoAsync(
   const char *host,
   const char *service,
   struct addrinfo *hint,
   std::function<void(struct addrinfo *, error *)> onResult,
   std::function<void(error *)> onError
);

enum ConnectAsyncStatus
{
   HostLookup,
   Connect,
};

void
ConnectAsync(
   const char *host,
   const char *service,
   std::function<void(ConnectAsyncStatus, const char *, error *)> onProgress,
   std::function<void(const std::shared_ptr<common::SocketHandle>, error *)> onResult,
   std::function<void(error *)> onError
);

} // end namespace

#endif
