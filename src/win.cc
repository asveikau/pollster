#include <pollster/socket.h>
#include <pollster/win.h>
#include <pollster/backends.h>

#include <common/misc.h>
#include <common/c++/new.h>

#include <string.h>

using namespace common;

namespace pollster { namespace windows {

struct handle_wrapper_base : virtual public pollster::event
{
   pollster::wait_loop *loop;
   HANDLE handle;

   handle_wrapper_base() : loop(nullptr), handle(INVALID_HANDLE_VALUE) {}
   ~handle_wrapper_base()
   {
      if (handle && handle != INVALID_HANDLE_VALUE)
         CloseHandle(handle);
   }

   void
   remove(error *err)
   {
      auto p = loop;
      loop = nullptr;

      if (p)
      {
         if (p->threadHelper.on_owning_thread())
            p->remove_handle(handle);
         else
         {
            Pointer<handle_wrapper_base> rcThis = this;

            p->threadHelper.enqueue_work(
               [rcThis, p] (error *err) -> void
               {
                  p->remove_handle(rcThis->handle);
               },
               err
            );
         }
      }
   }
};

struct socket_wrapper : public handle_wrapper_base, public pollster::socket_event
{
   SOCKET fd;

   socket_wrapper() : fd(INVALID_SOCKET) { writeable = true; }
   ~socket_wrapper() { if (fd != INVALID_SOCKET) closesocket(fd); }

   void
   create(SOCKET fd, bool write, error *err)
   {
      this->fd = fd;

      handle = CreateEvent(nullptr, FALSE, FALSE, nullptr);
      if (!handle)
         ERROR_SET(err, win32, GetLastError());

      set_needs_write(write, err);
      ERROR_CHECK(err);
   exit:;
   }

   void
   detach()
   {
      fd = INVALID_SOCKET;
   }

   void
   remove(error *err)
   {
      handle_wrapper_base::remove(err);
   }

   void
   set_needs_write(bool write, error *err)
   {
      const long basicEvents =
         FD_READ | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE;

      if (WSAEventSelect(fd, handle, basicEvents | (write ? FD_WRITE : 0)))
         ERROR_SET(err, win32, GetLastError());
   exit:;
   }
};

struct auto_reset_wrapper : public handle_wrapper_base, public pollster::auto_reset_signal
{
   void
   remove(error *err)
   {
      handle_wrapper_base::remove(err);
   }

   void
   create(error *err)
   {
      handle = CreateEvent(nullptr, FALSE, FALSE, nullptr);
      if (!handle)
         ERROR_SET(err, win32, GetLastError());
   exit:;
   }

   void
   signal(error *err)
   {
      if (!SetEvent(handle))
         ERROR_SET(err, win32, GetLastError());
   exit:;
   }
};

} } // end namespace

pollster::win_backend::win_backend()
{
   InitializeCriticalSection(&listLock);
   timer.thread_helper = &wait_loop.threadHelper;
}

pollster::win_backend::~win_backend()
{
   EnterCriticalSection(&listLock);
   auto p = wait_loop.get_next();
   while (p)
   {
      LeaveCriticalSection(&listLock);
      delete p;
      EnterCriticalSection(&listLock);
      p = wait_loop.get_next();
   }
   LeaveCriticalSection(&listLock);

   DeleteCriticalSection(&listLock);
}


void
pollster::win_backend::add(
   HANDLE handle,
   windows::handle_wrapper_base *ev,
   error *err
)
{
   pollster::wait_loop *to_delete = nullptr;

   if (wait_loop.threadHelper.on_owning_thread() &&
       wait_loop.slots_available())
      wait_loop.add_handle(handle, ev, err);
   else
   {
      EnterCriticalSection(&listLock);

      auto p = wait_loop.get_next();
      while (p)
      {
         auto q = p->get_next();

         if (p->slots_available())
         {
            common::Pointer<windows::handle_wrapper_base> evp = ev;
            p->enqueue_work(
               [this, p, handle, evp] (error *err) -> void
               {
                  p->add_handle(handle, evp.Get(), err);
                  ERROR_CHECK(err);
                  EnterCriticalSection(&listLock);
                  p->handicap--;
                  LeaveCriticalSection(&listLock);
               exit:;
               },
               err
            );
            ERROR_CHECK(err);

            p->handicap++;
            break;
         }

         p = q;
      }

      if (!p)
      {
         to_delete = p = new (std::nothrow) pollster::wait_loop(&listLock);
         if (!p)
            ERROR_SET(err, nomem);
         p->start_worker(err);
         ERROR_CHECK(err);

         common::Pointer<windows::handle_wrapper_base> evp = ev;
         p->enqueue_work(
            [p, handle, evp] (error *err) -> void
            {
               p->add_handle(handle, evp.Get(), err);
               ERROR_CHECK(err);
            exit:;
            },
            err
         );
         ERROR_CHECK(err);

         p->link(wait_loop.get_next_ptr());
         to_delete = nullptr;
      }

   exit:
      LeaveCriticalSection(&listLock);
      if (to_delete)
         delete to_delete;
   }
}

void
pollster::win_backend::exec(error *err)
{
   thread_helper_init init;
   init.backend = this;
   wait_loop.threadHelper.on_exec(&init, err);
   ERROR_CHECK(err);

   wait_loop.exec(&timer, err);
exit:;
}

void
pollster::win_backend::add_socket(
   SOCKET fd,
   bool write,
   socket_event **ev,
   error *err
)
{
   Pointer<windows::socket_wrapper> e;

   New(e.GetAddressOf(), err);
   ERROR_CHECK(err);

   e->create(fd, write, err);
   ERROR_CHECK(err);

   add(e->handle, e.Get(), err);
   ERROR_CHECK(err);

exit:
   if (!ERROR_FAILED(err))
      *ev = e.Detach();
}

void
pollster::win_backend::add_auto_reset_signal(
   bool repeating,
   auto_reset_signal **ev,
   error *err
)
{
   Pointer<windows::auto_reset_wrapper> e;

   New(e.GetAddressOf(), err);
   ERROR_CHECK(err);

   e->create(err);
   ERROR_CHECK(err);

   add(e->handle, e.Get(), err);
   ERROR_CHECK(err);

   if (!repeating)
   {
      auto p = e.Get();
      e->on_signal_impl = [p] (error *err) -> void
      {
         if (p->on_signal)
            p->on_signal(err);
         error_clear(err);
         p->remove(err);
         error_clear(err);       
      };
   }

exit:
   if (!ERROR_FAILED(err))
      *ev = e.Detach();
}

void
pollster::win_backend::add_timer(
   uint64_t millis,
   bool repeating,
   event **ev,
   error *err
)
{
   timer.add(millis, repeating, ev, err);
}

void
pollster::create_win(waiter **waiter, error *err)
{
   common::Pointer<win_backend> r;

   New(r.GetAddressOf(), err);
   ERROR_CHECK(err);

exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}

pollster::wait_loop::wait_loop(PCRITICAL_SECTION listLock_)
   : nHandles(0),
     workerThread(nullptr),
     workerMessageEvent(nullptr),
     shutdown(false),
     prev(nullptr),
     next(nullptr),
     listLock(listLock_),
     handicap(0)
{
   memset(handles, 0xff, sizeof(handles));
}

pollster::wait_loop::~wait_loop()
{
   if (workerThread)
   {
      messageQueue.synchronize(
         [&] () -> void
         {
            shutdown = true;
            SetEvent(workerMessageEvent);
         }
      );

      WaitForSingleObject(workerThread, INFINITE);
   }

   for (auto i = nHandles; --i; )
   {
      auto p = objects[i].Get();
      if (p)
         p->loop = nullptr;
   }

   if (workerThread)
      CloseHandle(workerThread);
   if (workerMessageEvent)
      CloseHandle(workerMessageEvent);
}

void
pollster::wait_loop::unlink(void)
{
   if (prev)
   {
      EnterCriticalSection(listLock);
      if (next)
         next->prev = prev;
      *prev = next;
      LeaveCriticalSection(listLock);

      next = nullptr;
      prev = nullptr;
   }
}

void
pollster::wait_loop::link(wait_loop **prev)
{
   prev = prev;
   next = *prev;
   *prev = this;
   if (next)
      next->prev = &next;
}

void
pollster::wait_loop::start_worker(error *err)
{
   if (workerThread)
      ERROR_SET(err, unknown, "Thread already started");
   if (nHandles)
      ERROR_SET(err, unknown, "Handle list already non-empty");

   messageQueue.initialize(err);
   ERROR_CHECK(err);

   if (!workerMessageEvent)
      workerMessageEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
   if (!workerMessageEvent)
      ERROR_SET(err, win32, GetLastError());

   {
      auto handle = workerMessageEvent;
      messageQueue.on_enqueue = [handle] (error *err) -> void
      {
         if (!SetEvent(handle))
            ERROR_SET(err, win32, GetLastError());
      exit:;
      };
   }

   handles[0] = workerMessageEvent;
   objects[0] = nullptr;
   nHandles++;

   workerThread = CreateThread(
      nullptr,
      0,
      ThreadProcStatic,
      this,
      0,
      nullptr
   );
   if (!workerThread)
      ERROR_SET(err, win32, GetLastError());
exit:;
}

void
pollster::wait_loop::ThreadProc(error *err)
{
   bool selfShutdown = false;

   {
      thread_helper_init init;
      init.queue = &messageQueue;
      threadHelper.on_exec(&init, err);
      ERROR_CHECK(err);
   }

   while (!shutdown)
   {
      exec(nullptr, err);
      ERROR_CHECK(err);

      if (nHandles == 1)
      {
         messageQueue.synchronize(
            [&] () -> void
            {
               if (nHandles == 1 && messageQueue.is_empty())
                  selfShutdown = shutdown = true;
            }
         );
      }
   }

exit:

   unlink();

   if (ERROR_FAILED(err) && !shutdown)
   {
      messageQueue.synchronize(
         [&] () -> void
         {
            selfShutdown = shutdown = true;
            // XXX: what if there are jobs in the queue?            
         }
      );
   }

   if (selfShutdown)
   {
      auto h = workerThread;
      workerThread = nullptr;
      CloseHandle(h);
      delete this;
   }
}

DWORD WINAPI
pollster::wait_loop::ThreadProcStatic(PVOID thisp)
{
   wait_loop *This = (wait_loop*)thisp;
   error err;
   This->ThreadProc(&err);
   return ERROR_FAILED(&err);
}

bool
pollster::wait_loop::enqueue_work(std::function<void(error*)> func, error *err)
{
   bool r = false;

   if (!workerThread)
      ERROR_SET(err, unknown, "worker thread not started");

   r = messageQueue.enqueue_work(func, shutdown, err);
   ERROR_CHECK(err);
exit:
   return r;
}

int
pollster::wait_loop::slots_available(void)
{
   auto slots = ARRAY_SIZE(handles) - nHandles - handicap;
   return MAX(slots, 0);
}

void
pollster::wait_loop::add_handle(HANDLE h, windows::handle_wrapper_base *object, error *err)
{
   if (nHandles == ARRAY_SIZE(handles))
      ERROR_SET(err, unknown, "Exceeded limit of handles");

   if (object)
   {
      object->loop = this;
   }
   handles[nHandles] = h;
   objects[nHandles] = object;
   ++nHandles;
exit:;
}

int
pollster::wait_loop::find_handle(HANDLE h)
{
   for (int i=0; i<nHandles; ++i)
      if (handles[i] == h)
         return i;
   return -1;
}


void
pollster::wait_loop::remove_handle(HANDLE h)
{
   auto i = find_handle(h);
   if (i >= 0)
   {
      if (i != nHandles - 1)
      {
         handles[i] = handles[nHandles - 1];
         objects[i] = std::move(objects[nHandles - 1]);
      }
      --nHandles;
      handles[nHandles] = INVALID_HANDLE_VALUE;
      objects[nHandles] = nullptr;
   }
}

void
pollster::wait_loop::exec(timer *optional_timer, error *err)
{
   DWORD result = 0;
   DWORD timeout = INFINITE;
   int idx = -1;

   if (optional_timer)
   {
      auto t = optional_timer->next_timer();
      if (t >= 0)
      {
         const DWORD max = (DWORD)~0;
         if (t > max)
            t = max;
         timeout = t;

         optional_timer->begin_poll(err);
         ERROR_CHECK(err);
      }
      else
      {
         optional_timer = nullptr;
      }
   }

   if (!nHandles && timeout == INFINITE)
      ERROR_SET(err, unknown, "exec() called with empty fd set");

   result = WaitForMultipleObjects(
      nHandles,
      handles,
      FALSE,
      timeout
   );
   if (result == WAIT_FAILED)
      ERROR_SET(err, win32, GetLastError());
   else if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0+nHandles)
      idx = result - WAIT_OBJECT_0;
   else if (result >= WAIT_ABANDONED_0 && result < WAIT_ABANDONED_0+nHandles)
      idx = result - WAIT_ABANDONED_0;

   if (idx >= 0)
   {
      if (workerMessageEvent && handles[idx] == workerMessageEvent)
      {
         messageQueue.drain(err);
         ERROR_CHECK(err);
      }
      else
      {
         objects[idx]->signal_from_backend(err);
         ERROR_CHECK(err);
      }
   }

   if (optional_timer)
   {
      optional_timer->end_poll(err);
      ERROR_CHECK(err);
   }

exit:;
}