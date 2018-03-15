#ifndef pollster_win_h_
#define pollster_win_h_

#include "pollster.h"
#include "timer.h"

#include <vector>
#include <functional>

namespace pollster {

class wait_loop
{
   common::Pointer<event> objects[MAXIMUM_WAIT_OBJECTS];
   HANDLE handles[MAXIMUM_WAIT_OBJECTS];
   int nHandles;

   PCRITICAL_SECTION lock;
   CRITICAL_SECTION lockStorage;
   HANDLE workerThread;
   HANDLE workerMessageEvent;
   std::vector<std::function<void(error*)>> messageQueue;
   bool shutdown;

   int
   find_handle(HANDLE h);

   static DWORD WINAPI
   ThreadProcStatic(PVOID thisp);

   void
   ThreadProc(error *err);

public:
   wait_loop();
   wait_loop(const wait_loop&) = delete;
   ~wait_loop();

   void
   start_worker(error *err);

   // Returns false if thread is shutting down.
   //
   bool
   enqueue_work(std::function<void(error*)> func, error *err);

   int
   slots_available(void);

   void
   add_handle(HANDLE h, event *object, error *err);

   void
   remove_handle(HANDLE h);

   void
   exec(timer *optional_timer, error *err);
};

struct win_backend : public waiter
{
   timer timer;
   wait_loop wait_loop;

   void
   add(HANDLE handle, event *object, error *err);

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
