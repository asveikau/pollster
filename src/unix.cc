#include <unistd.h>
#include <fcntl.h>

#include <pollster/unix.h>
#include <pthread.h>
#include <signal.h>

using namespace common;

namespace {

struct fd_wrapper_base : virtual public pollster::event
{
   pollster::unix_backend *p;
   int fd;
   bool detached;

   fd_wrapper_base() : p(nullptr), fd(-1), detached(false) {}
   ~fd_wrapper_base() { closeFd(); }

   void
   closeFd(void)
   {
      if (fd >= 0 && !detached)
         close(fd);
      fd = -1;
   }

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

      closeFd();

      if (removed)
         Release();
   }

   void
   detach()
   {
      detached = true;
   }
};

struct socket_wrapper : public fd_wrapper_base, public pollster::socket_event
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

   void
   detach()
   {
      fd_wrapper_base::detach();      
   }
};

struct auto_reset_wrapper : public fd_wrapper_base, public pollster::auto_reset_signal
{
   int writefd;
   bool repeat;

   auto_reset_wrapper() : writefd(-1), repeat(false) {}
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
#define exit innerExit
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

         ERROR_CHECK(err);

         if (!repeat)
            remove(err); 
      exit:;
#undef exit
      };
   exit:;
   }

   void
   signal(error *err)
   {
      char ch = 0;
      int r = 0;
      sigset_t sigset, old;
      bool masked = false;

      sigemptyset(&sigset);
      sigaddset(&sigset, SIGPIPE);

      if (pthread_sigmask(SIG_BLOCK, &sigset, &old))
         ERROR_SET(err, errno, errno);

      masked = true;

      r = write(writefd, &ch, 1);
      if (r < 0)
         ERROR_SET(err, errno, errno);
      if (r != 1)
         ERROR_SET(err, unknown, "write: unexpected return value");
   exit:
      if (err->source == ERROR_SRC_ERRNO && err->code == EPIPE)
      {
         int sig = SIGPIPE;
         sigwait(&sigset, &sig);
      }
      if (masked)
         pthread_sigmask(SIG_SETMASK, &old, nullptr);
   }
};

} // end namespace

void
pollster::unix_backend::add_socket(
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
pollster::unix_backend::add_auto_reset_signal(
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
   e->repeat = repeating;

exit:
   if (!ERROR_FAILED(err))
      *ev = e.Detach();
}

void
pollster::unix_backend::add_timer(
   uint64_t millis,
   bool repeating,
   event **ev,
   error *err
)
{
   timer.add(millis, repeating, ev, err);
}
