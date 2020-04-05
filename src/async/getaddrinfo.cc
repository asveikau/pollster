/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// This is a default implementation which creates a thread per request.
// Hopefully we'll do better in other implementations but this is a
// baseline to validate the abstraction and provide a least common
// denominator.
//

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <common/thread.h>

#include <string>

using pollster::error_set_gai;

void
pollster::GetAddrInfoAsync(
   const char *host_,
   const char *service_,
   struct addrinfo *hint_,
   const std::function<void(const std::shared_ptr<struct addrinfo> &, error *err)> &onResult,
   const std::function<void(error *)> &onError
)
{
   error err;
   thread_id id = {0};
   struct addrinfo hint = {0};
   bool hasHint = false;

   socket_startup(&err);
   ERROR_CHECK(&err);

   if (hint_)
   {
      hasHint = true;
      hint = *hint_;
   }

   try
   {
      std::string host = host_;
      std::string service = service_;

      common::create_thread(
         [host, service, hint, hasHint, onResult, onError] () -> void
         {
            error err;
            struct addrinfo *info = nullptr;
            std::shared_ptr<addrinfo> infop;
            int r = getaddrinfo(
               host.c_str(),
               service.c_str(),
               hasHint ? &hint : nullptr,
               &info
            );
            if (r)
               ERROR_SET(&err, gai, r);
            try
            {
               infop = std::shared_ptr<addrinfo>(info, freeaddrinfo);
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(&err, nomem);
            }
            info = nullptr;
            onResult(infop, &err);
            ERROR_CHECK(&err);
         exit:
            if (info)
               freeaddrinfo(info);
            if (ERROR_FAILED(&err) && onError)
               onError(&err);
         },
         &id,
         &err
      );
      ERROR_CHECK(&err);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

   detach_thread(&id);

exit:
   if (ERROR_FAILED(&err) && onError)
      onError(&err);
}