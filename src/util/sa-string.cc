/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <common/misc.h>

#include <string.h>

#if !defined(_WINDOWS)

static void
get_addr(struct sockaddr *sa, void *&p, socklen_t &len)
{
   switch (sa->sa_family)
   {
   case AF_INET:
      {
         auto in = (struct sockaddr_in*)sa;
         p = &in->sin_addr;
         len = sizeof(in->sin_addr);
      }
      break;
   case AF_INET6:
      {
         auto in6 = (struct sockaddr_in6*)sa;
         p = &in6->sin6_addr;
         len = sizeof(in6->sin6_addr);
      }
      break;
   default:
      p = NULL;
      len = 0;
   }
}

#endif

const char *
pollster::sockaddr_to_string(struct sockaddr *sa, char *buf, socklen_t len)
{
   if (len <= 0)
      return NULL;

   if (sa->sa_family == AF_UNIX)
   {
      auto un = (struct sockaddr_un*)sa;
      auto sun_len = strlen(un->sun_path);
      if (len < sun_len + 1)
         return NULL;
      memcpy(buf, un->sun_path, sun_len+1);
      return buf;
   }

#if defined(_WINDOWS)
   DWORD len2 = MIN(((DWORD)~0UL), len);
   if (WSAAddressToStringA(sa, socklen(sa), nullptr, buf, &len2))
      return NULL;
   // Strip port, as Unix doesn't include it.
   char *p;
   switch (sa->sa_family)
   {
   case AF_INET:
      if ((p = strchr(buf, ':')))
         *p = 0;
      break;
   case AF_INET6:
      if (buf[0] == '[' && (p=strchr(buf+1, ']')))
      {
         *p = 0;
         memmove(buf, buf+1, p-buf);
      }
      break;
   }
   return buf;
#else
   void *p = NULL;
   socklen_t slen = 0;

   get_addr(sa, p, slen);
   if (!p)
      return NULL;
   return inet_ntop(sa->sa_family, p, buf, len);
#endif
}

bool
pollster::string_to_sockaddr(struct sockaddr *sa, const char *str)
{
   if (sa->sa_family == AF_UNIX)
   {
      error err;
      sockaddr_un_set((struct sockaddr_un*)sa, str, &err);
      return !ERROR_FAILED(&err);
   }

#if defined(_WINDOWS)
   INT len = socklen(sa);
   return !WSAStringToAddressA((PSTR)str, sa->sa_family, nullptr, sa, &len);
#else
   void *p = NULL;
   socklen_t len = 0;

   get_addr(sa, p, len);
   if (!p)
      return false;

   return inet_pton(sa->sa_family, str, p) > 0;
#endif
}
