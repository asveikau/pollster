/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <common/c++/refcount.h>
#include <common/c++/new.h>
#include <common/size.h>

#include <stdlib.h>
#include <string.h>

using pollster::error_set_gai;

namespace {

struct State : public common::RefCountable
{
   struct gaicb cb;
   struct addrinfo hint;
   void *onHeap;
   std::function<void(struct addrinfo *, error *err)> onResult;
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
   std::function<void(struct addrinfo *, error *err)> onResult,
   std::function<void(error *)> onError
)
{
   error err;
   common::Pointer<State> state;
   gaicb *cb = nullptr;
   size_t hostlen = strlen(host);
   size_t svclen = strlen(service); 
   size_t n = 0;
   struct sigevent sev = {0};
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

   sev.sigev_notify = SIGEV_THREAD;
   sev.sigev_value.sival_ptr = state.Get();
   sev.sigev_notify_function = [] (union sigval val) -> void
   {
      State *state = (State*)val.sival_ptr;
      error err;
      int r = 0;

      r = gai_error(&state->cb);
      if (r)
         ERROR_SET(&err, gai, r);

      state->onResult(state->cb.ar_result, &err);
      ERROR_CHECK(&err);

   exit:
      if (ERROR_FAILED(&err) && state->onError)
         state->onError(&err);
      state->Release();
   };

   cb = &state->cb;
   state->AddRef();
   r = getaddrinfo_a(GAI_NOWAIT, &cb, 1, &sev);
   if (r)
   {
      state->Release();
      ERROR_SET(&err, gai, r);
   }

exit:
   if (ERROR_FAILED(&err) && onError)
      onError(&err);
}
