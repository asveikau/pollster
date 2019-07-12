/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>

int
pollster::socklen(int af)
{
   switch (af)
   {
   case AF_INET:
      return sizeof(struct sockaddr_in);
   case AF_INET6:
      return sizeof(struct sockaddr_in6);
#if defined(AF_UNIX)
   case AF_UNIX:
      return sizeof(struct sockaddr_un);
#endif
   }
   return -1;
}

int
pollster::socklen(struct sockaddr *sa)
{
#ifdef HAVE_SA_LEN
   return sa->sa_len;
#else
   return socklen(sa->sa_family);
#endif
}

void
pollster::sockaddr_set_af(struct sockaddr *sa, int af)
{
   sa->sa_family = af;
#ifdef HAVE_SA_LEN
   sa->sa_len = socklen(af);
#endif
}