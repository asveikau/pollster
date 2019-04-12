/*
 Copyright (C) 2018-2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// This file contains a few ifdef'd delclarations to make porting to
// Windows easier.  For more of a high-level socket API, see sockapi.h
//

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

#define SOCKET_LASTERROR GetLastError()
#define SOCK_ERROR(c)    WSA##c

static INLINE
void
error_set_socket(error *err, DWORD dw)
{
   error_set_win32(err, dw);
}

static INLINE
void
error_set_socket(error *err);

static INLINE
void
set_nonblock(SOCKET fd, bool on, error *err)
{
   unsigned long onl = on ? 1L : 0L;
   if (ioctlsocket(fd, FIONBIO, &onl))
      ERROR_SET(err, socket);
exit:;
}

namespace pollster
{

void
socket_startup(error *err);

} // end namepsace

static INLINE
int
getsockopt_compat(SOCKET sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
   return getsockopt(sockfd, level, optname, (char*)optval, optlen);
}
static INLINE
int
setsockopt_compat(SOCKET sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
   return setsockopt(sockfd, level, optname, (const char*)optval, optlen);
}
#define getsockopt getsockopt_compat
#define setsockopt setsockopt_compat

#else

#include <common/mutex.h> // XXX - workaround for Sun mutex name conflict.

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

#define SOCKET_LASTERROR errno
#define SOCK_ERROR(c)    c

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

static INLINE
void
error_set_socket(error *err, int r)
{
   error_set_errno(err, r);
}

static INLINE
void
error_set_socket(error *err);

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

static INLINE
void
error_set_socket(error *err)
{
   error_set_socket(err, SOCKET_LASTERROR);
}

namespace pollster
{
   void
   error_set_gai(error *err, int r);

   int
   socklen(int af);

   int
   socklen(struct sockaddr *);

   void
   sockaddr_set_af(struct sockaddr *, int af);

   static inline void
   sockaddr_set_af(struct sockaddr_in *in)
   {
      sockaddr_set_af((sockaddr*)in, AF_INET);
   }

   static inline void
   sockaddr_set_af(struct sockaddr_in6 *in6)
   {
      sockaddr_set_af((sockaddr*)in6, AF_INET6);
   }
}

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#define HAVE_SA_LEN 1
#endif

#endif
