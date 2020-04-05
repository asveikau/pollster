/*
 Copyright (C) 2018-2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <common/lazy.h>

void
pollster::socket_startup(error *err)
{
   static lazy_init_state lazy = {0};

   lazy_init(
      &lazy,
      [] (void *ctx, error *err) -> void
      {
         WSADATA data = {0};
         if (WSAStartup(MAKEWORD(2,2), &data))
            ERROR_SET(err, win32, GetLastError());
      exit:;
      },
      nullptr,
      err
   );
ERROR_CHECK(err);
exit:;
}
