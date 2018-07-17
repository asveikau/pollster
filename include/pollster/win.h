#ifndef pollster_win_h_
#define pollster_win_h_

#include "pollster.h"
#include "timer.h"
#include "messagequeue.h"
#include "threads.h"

#include <vector>
#include <functional>

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
   enqueue_work(std::function<void(error*)> func, error *err);

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
      SOCKET fd,
      bool write,
      socket_event **ev,
      error *err
   );

   void
   add_auto_reset_signal(
      bool repeating,
      auto_reset_signal **ev,
      error *err
   );

   void
   add_timer(
      uint64_t millis,
      bool repeating,
      event **ev,
      error *err
   );

   void
   exec(error *err);
};

} // end namespace


#endif
