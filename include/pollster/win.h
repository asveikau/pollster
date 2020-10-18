/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_win_h_
#define pollster_win_h_

#include "pollster.h"
#include "timer.h"
#include "messagequeue.h"
#include "threads.h"

#include <vector>
#include <functional>
#include <memory>

namespace pollster {

namespace windows
{
   struct handle_wrapper_base;
}

class wait_loop
{
   common::Pointer<windows::handle_wrapper_base> objects[MAXIMUM_WAIT_OBJECTS];
   HANDLE handles[MAXIMUM_WAIT_OBJECTS];
   int nHandles;

   message_queue messageQueue;
   HANDLE workerThread;
   HANDLE workerMessageEvent;
   bool shutdown;
   wait_loop **prev, *next;
   PCRITICAL_SECTION listLock;

   void
   unlink(void);

   int
   find_handle(HANDLE h);

   static DWORD WINAPI
   ThreadProcStatic(PVOID thisp);

   void
   ThreadProc(error *err);

public:
   wait_loop(PCRITICAL_SECTION listLock = nullptr);
   wait_loop(const wait_loop&) = delete;
   ~wait_loop();

   thread_helper threadHelper;

   int handicap;

   void
   link(wait_loop **prev);

   wait_loop *
   get_next(void) { return next; }

   wait_loop **
   get_next_ptr(void) { return &next; }

   void
   start_worker(error *err);

   // Returns false if thread is shutting down.
   //
   bool
   enqueue_work(const std::function<void(error*)> &func, error *err);

   int
   slots_available(void);

   void
   add_handle(HANDLE h, windows::handle_wrapper_base *object, error *err);

   void
   remove_handle(HANDLE h);

   void
   exec(timer *optional_timer, error *err);
};

struct win_backend : public waiter
{
   timer timer;
   wait_loop wait_loop;
   CRITICAL_SECTION listLock;

   win_backend();
   ~win_backend();

   void
   add(HANDLE handle, windows::handle_wrapper_base *object, error *err);

   void
   add_socket(
      const std::shared_ptr<common::SocketHandle> &fd,
      bool write,
      const std::function<void(socket_event*, error *)> &initialize,
      socket_event **ev,
      error *err
   );

   void
   add_auto_reset_signal(
      bool repeating,
      const std::function<void(auto_reset_signal*, error *)> &initialize,
      auto_reset_signal **ev,
      error *err
   );

   void
   add_timer(
      uint64_t millis,
      bool repeating,
      const std::function<void(event*, error *)> &initialize,
      event **ev,
      error *err
   );

   void
   exec(error *err);
};

namespace windows
{
   void
   CreateOverlapped(
      waiter *w,
      const std::function<void (error *)> &on_error,
      const std::function<void (DWORD, OVERLAPPED*, error *)> &on_result,
      OVERLAPPED **res,
      LPOVERLAPPED_COMPLETION_ROUTINE *fn,
      error *err
   );

   void
   FreeOverlapped(OVERLAPPED *);

   void
   ReadFileAsync(
      waiter *w,
      const std::shared_ptr<common::FileHandle> &file,
      const uint64_t *offset_opt,
      void *buffer,
      size_t len,
      const std::function<void(error *)> &on_error,
      const std::function<void(size_t, error *)> &on_result
   );

   void
   WriteFileAsync(
      waiter *w,
      const std::shared_ptr<common::FileHandle> &file,
      const uint64_t *offset_opt,
      const void *buffer,
      size_t len,
      const std::function<void(error *)> &on_error,
      const std::function<void(size_t, error *)> &on_result
   );

   void
   CreateLegacyAfUnixServer(
      waiter *w,
      struct sockaddr_un *sun,
      const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
      error *err
   );

   void
   CreateLegacyAfUnixClient(
      waiter *w,
      struct sockaddr_un *sun,
      const std::function<void (const std::shared_ptr<common::FileHandle> &, error *)> &on_client,
      error *err
   );

   void
   BindLegacyAfUnixClient(
      waiter *w,
      const std::shared_ptr<common::FileHandle> &hClient,
      std::function<void(const void *buf, size_t len, const std::function<void(error*)> &onComplete, error *err)> &writeFn,
      const std::function<void(const void *, size_t, error *)> &on_recv,
      const std::function<void(error *)> &on_closed,
      const std::function<void(error *)> &on_error,
      error *err
   );
}

} // end namespace

#endif
