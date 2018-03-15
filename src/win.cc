#include <pollster/socket.h>
#include <pollster/win.h>
#include <pollster/backends.h>

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
