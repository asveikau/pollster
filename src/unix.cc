#include <unistd.h>
#include <fcntl.h>

#include <wait/unix.h>

using namespace common;

namespace {

struct fd_wrapper_base : virtual public wait::event
{
   wait::unix_backend *p;
   int fd;

   fd_wrapper_base() : p(nullptr), fd(-1) {}

   void
   remove(error *err)
   {
      bool removed = false;

      if (p && fd >= 0)
      {
         AddRef();
         p->remove_fd(fd, this, err);
         removed = true;
      }

      p = nullptr;

      if (fd >= 0)
      {
         close(fd);
         fd = -1;
      }

      if (removed)
         Release();
   }
};

struct socket_wrapper : public fd_wrapper_base, public wait::socket_event
{
   socket_wrapper() { writeable = true; }

   void
   remove(error *err)
   {
      fd_wrapper_base::remove(err);
   }

   void
   set_needs_write(bool write, error *err)
   {
      if (p && fd >= 0)
      {
         p->set_write(fd, write, this, err);
      }
   }
};

struct auto_reset_wrapper : public fd_wrapper_base, public wait::auto_reset_signal
{
   int writefd;

   auto_reset_wrapper() : writefd(-1) {}
   ~auto_reset_wrapper() { if (writefd >= 0) close(writefd);}

   void
   remove(error *err)
   {
      fd_wrapper_base::remove(err);
   }

   void
   create(error *err)
   {
      int p[2];

      if (pipe(p))
         ERROR_SET(err, errno, errno);

      writefd = p[1];
      fd = p[0];

      if (fcntl(fd, F_SETFL, O_NONBLOCK, 1))
         ERROR_SET(err, errno, errno);

      on_signal_impl = [this] (error *err) -> void
      {
         int r = 0;
         char buf[64];

         while ((r = read(fd, buf, sizeof(buf))) > 0);

         if (r < 0)
         {
            switch (errno)
            {
            case EAGAIN:
            case EINTR:
               break;
            default:
               ERROR_SET(err, errno, errno);
            }
         }

         if (on_signal)
            on_signal(err);
      exit:;
      };
   exit:;
   }

   void
   signal(error *err)
   {
      char ch = 0;
      int r = write(writefd, &ch, 1);
      if (r < 0)
         ERROR_SET(err, errno, errno);
      if (r != 1)
         ERROR_SET(err, unknown, "write: unexpected return value");
   exit:;
   }
};

} // end namespace

void
wait::unix_backend::add_socket(
   int fd,
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

   add_fd(fd, write, e.Get(), err);
   ERROR_CHECK(err);

   e->p = this;
   e->fd = fd;

exit:
   if (!ERROR_FAILED(err))
      *ev = e.Detach();
}

void
wait::unix_backend::add_auto_reset_signal(
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

   add_fd(e->fd, false, e.Get(), err);
   ERROR_CHECK(err);

   e->p = this;

exit:
   if (!ERROR_FAILED(err))
      *ev = e.Detach();
}

void
wait::unix_backend::add_timer(
   uint64_t millis,
   bool repeating,
   event **ev,
   error *err
)
{
   ERROR_SET(err, unknown, "Not implemented");
exit:;
}

int64_t
wait::unix_backend::get_timeout(void)
{
   return -1;
}
