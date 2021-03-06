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
#include <common/size.h>

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

static INLINE
int
sendto_compat(SOCKET sockfd, const void *buf, int len, int flags, const sockaddr *addr, int addrlen)
{
   return sendto(sockfd, (const char*)buf, len, flags, addr, addrlen);
}
static INLINE
int
recvfrom_compat(SOCKET sockfd, void *buf, int len, int flags, sockaddr *addr, int *addrlen)
{
   return recvfrom(sockfd, (char*)buf, len, flags, addr, addrlen);
}
#define sendto   sendto_compat
#define recvfrom recvfrom_compat

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

namespace pollster
{

static inline void
socket_startup(error *err)
{
}

} // end namepsace

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
   socklen(const struct sockaddr *);

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

   const char *
   sockaddr_to_string(struct sockaddr *sa, char *buf, socklen_t len);

   bool
   string_to_sockaddr(struct sockaddr *sa, const char *str);

   extern
   bool
   AbstractAfUnixSupported;
}

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#define HAVE_SA_LEN 1
#endif

#if defined(AF_UNIX)
#if defined(_WINDOWS)
// XXX, should include <afunix.h>, but would require greater SDK than
// sometimes built with.
#define UNIX_PATH_MAX 108
typedef struct sockaddr_un
{
   ADDRESS_FAMILY sun_family;
   char sun_path[UNIX_PATH_MAX];
} SOCKADDR_UN, *PSOCKADDR_UN;
#else
#include <sys/un.h>
#endif
#endif

namespace pollster
{
void
sockaddr_un_set(struct sockaddr_un *addr, const char *path, error *err);

#if defined(_WINDOWS)
typedef int sendrecv_retval, sendrecv_size;
#define SENDRECV_MAX INT_MAX
#else
typedef ssize_t sendrecv_retval;
typedef size_t sendrecv_size;
#define SENDRECV_MAX ((size_t)SSIZE_MAX)
#endif

} // end namespace

#endif
