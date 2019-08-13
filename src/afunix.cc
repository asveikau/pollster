/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <common/path.h>
#include <string.h>

#if defined(__linux__) || defined(_WINDOWS)
#define HAVE_ABSTRACT_SOCKETS 1
#else
#define HAVE_ABSTRACT_SOCKETS 0
#endif

bool
pollster::AbstractAfUnixSupported = HAVE_ABSTRACT_SOCKETS;

void
pollster::sockaddr_un_set(struct sockaddr_un *addr, const char *path, error *err)
{
   size_t avail = ARRAY_SIZE(addr->sun_path);
   size_t n = 0;
#if !HAVE_ABSTRACT_SOCKETS
   char *heapBuffer = nullptr;
#endif

   auto dst = addr->sun_path;

   sockaddr_set_af((sockaddr*)addr, AF_UNIX);
   memset(addr->sun_path, 0, sizeof(addr->sun_path));

   // Extension: 0 byte plus string means non-filesystem socket.
   //
   if (!*path && path[1])
   {
#if !HAVE_ABSTRACT_SOCKETS
      char *p = nullptr;
      heapBuffer = get_private_dir(0, err);
      ERROR_CHECK(err);
      heapBuffer = append_path(p = heapBuffer, "sockets", err);
      free(p);
      ERROR_CHECK(err);
      secure_mkdir(heapBuffer, err);
      heapBuffer = append_path(p = heapBuffer, path+1, err);
      free(p);
      ERROR_CHECK(err);

      path = heapBuffer;
#else
      --avail;
      dst++;
      path++;
#endif
   }

   n = strlen(path);

   if (n > avail)
      ERROR_SET(err, unknown, "Path too large");

   memcpy(dst, path, n);
exit:;
#if !HAVE_ABSTRACT_SOCKETS
   free(heapBuffer);
#endif
}
