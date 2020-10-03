/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <common/c++/refcount.h>
#include <common/c++/new.h>
#include <common/size.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>

using pollster::error_set_gai;

namespace {

struct State : public common::RefCountable
{
   struct gaicb cb;
   struct addrinfo hint;
   struct sigevent sev;
   void *onHeap;
   std::function<void(const std::shared_ptr<struct addrinfo> &, error *err)> onResult;
   std::function<void(error *)> onError;

   State() : onHeap(nullptr)
   {
      memset(&cb, 0, sizeof(cb));
      memset(&hint, 0, sizeof(hint));
   }

   State(const State &) = delete;

   ~State()
   {
      free(onHeap);
      if (cb.ar_result)
         freeaddrinfo(cb.ar_result);
   }
};

} // end namespace

void
pollster::GetAddrInfoAsync(
   const char *host,
   const char *service,
   struct addrinfo *hint,
   const std::function<void(const std::shared_ptr<struct addrinfo> &, error *err)> &onResult,
   const std::function<void(error *)> &onError
)
{
   error err;
   common::Pointer<State> state;
   common::Pointer<pollster::waiter> queue;
   common::Pointer<pollster::sigev_extif> sigevExt;
   gaicb *cb = nullptr;
   size_t hostlen = strlen(host);
   size_t svclen = strlen(service); 
   size_t n = 0;
   int r = 0;

   if (size_add(hostlen, svclen, &n) ||
       size_add(n, 2, &n))
      ERROR_SET(&err, unknown, "Integer overflow");

   New(state, &err);
   ERROR_CHECK(&err);

   try
   {
      state->onResult = std::move(onResult);
      state->onError = onError;
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

   state->onHeap = malloc(n);
   if (!state->onHeap)
      ERROR_SET(&err, nomem);

   memcpy(state->onHeap, host, hostlen+1);
   host = (char*)state->onHeap;
   memcpy((char*)state->onHeap+hostlen+1, service, svclen+1);
   service = (char*)state->onHeap+hostlen+1;

   if (hint)
   {
      state->hint = *hint;
      hint = &state->hint;
   }

   state->cb.ar_name = host;
   state->cb.ar_service = service;
   state->cb.ar_request = hint;

   pollster::get_common_queue(queue.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   *sigevExt.GetAddressOf() = (pollster::sigev_extif*)queue->get_interface(pollster::SigEvent, &err); 
   ERROR_CHECK(&err);
   if (!sigevExt.Get())
      ERROR_SET(&err, unknown, "No sigev support");

   sigevExt->wrap_sigev(
      &state->sev,
      [state] (error *err) -> void
      {
         std::shared_ptr<struct addrinfo> info;
         int r = 0;

         r = gai_error(&state->cb);
         if (r)
            ERROR_SET(err, gai, r);

         try
         {
            info = std::shared_ptr<struct addrinfo>(state->cb.ar_result, freeaddrinfo);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
         state->cb.ar_result = nullptr;

         state->onResult(info, err);
         ERROR_CHECK(err);
      exit:
         if (ERROR_FAILED(err) && state->onError)
            state->onError(err);
         error_clear(err);
      },
      [state] (error *err) -> void
      {
         if (state->onError)
            state->onError(err);
      },
      &err
   );
   ERROR_CHECK(&err);

   cb = &state->cb;
   r = getaddrinfo_a(GAI_NOWAIT, &cb, 1, &state->sev);
   if (r)
   {
      if (sigevExt.Get())
         sigevExt->remove_sigev(&state->sev);
      ERROR_SET(&err, gai, r);
   }

exit:
   if (ERROR_FAILED(&err) && onError)
      onError(&err);
}
