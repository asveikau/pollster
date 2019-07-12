/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <string.h>

void
pollster::sockaddr_un_set(struct sockaddr_un *addr, const char *path, error *err)
{
   size_t avail = ARRAY_SIZE(addr->sun_path);
   size_t n = 0;

   auto dst = addr->sun_path;

   sockaddr_set_af((sockaddr*)addr, AF_UNIX);
   memset(addr->sun_path, 0, sizeof(addr->sun_path));

   // Extension: 0 byte plus string means non-filesystem socket.
   //
   if (!*path && path[1])
   {
      --avail;
      dst++;
      path++;
   }

   n = strlen(path);

   if (n > avail)
      ERROR_SET(err, unknown, "Path too large");

   memcpy(dst, path, n);
exit:;
}
