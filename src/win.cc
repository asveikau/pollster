#include <pollster/socket.h>
#include <pollster/win.h>
#include <pollster/backends.h>

#include <string.h>

using namespace common;

namespace {

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
      if (loop)
      {
         loop->remove_handle(handle);
         loop = nullptr;
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
   bool repeat;

   auto_reset_wrapper() : repeat(false) {}

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

} // end namespace

void
pollster::win_backend::add(
   HANDLE handle,
   pollster::event *ev,
   error *err
)
{
   if (wait_loop.slots_available())
      wait_loop.add_handle(handle, ev, err);
   else
   {
      // TODO
   }
}

void
pollster::win_backend::exec(error *err)
{
   wait_loop.exec(&timer, err);
}

void
pollster::win_backend::add_socket(
   SOCKET fd,
   bool write,
   socket_event **ev,
   error *err
)
{
   Pointer<socket_wrapper> e;

   try
   {
      *e.GetAddressOf() = new socket_wrapper();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

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
   Pointer<auto_reset_wrapper> e;

   try
   {
      *e.GetAddressOf() = new auto_reset_wrapper();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   e->create(err);
   ERROR_CHECK(err);

   add(e->handle, e.Get(), err);
   ERROR_CHECK(err);

   e->repeat = repeating;

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

   try
   {
      *r.GetAddressOf() = new win_backend();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

exit:
   if (!ERROR_FAILED(err))
      *waiter = r.Detach();
}

pollster::wait_loop::wait_loop(bool slave)
   : nHandles(0)
{
   memset(handles, 0xff, sizeof(handles));
}

pollster::wait_loop::~wait_loop()
{
}

int
pollster::wait_loop::slots_available(void)
{
   return ARRAY_SIZE(handles) - nHandles;
}

void
pollster::wait_loop::add_handle(HANDLE h, event *object, error *err)
{
   if (nHandles == ARRAY_SIZE(handles))
      ERROR_SET(err, unknown, "Exceeded limit of handles");

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
      objects[idx]->signal_from_backend(err);
      ERROR_CHECK(err);
   }

   if (optional_timer)
   {
      optional_timer->end_poll(err);
      ERROR_CHECK(err);
   }

exit:;
}