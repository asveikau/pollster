/*
 Copyright (C) 2018 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <unistd.h>
#include <fcntl.h>

#include <common/c++/new.h>

#include <pollster/unix.h>
#include <pthread.h>
#include <signal.h>

#if defined(__linux__) && !defined(USE_EVENTFD)
#define USE_EVENTFD 1
#endif

#ifdef USE_EVENTFD
#include <sys/eventfd.h>
#endif

using namespace common;

namespace {

struct fd_wrapper_base : virtual public pollster::event
{
   pollster::unix_backend *p;
   std::shared_ptr<FileHandle> fd;

   fd_wrapper_base() : p(nullptr) {}

   void
   remove(error *err)
   {
      auto q = p;
      p = nullptr;

      if (q && fd->Valid())
      {
         if (!q->thread_helper.on_owning_thread())
         {
            Pointer<fd_wrapper_base> rcThis = this;

            q->thread_helper.enqueue_work(
               [rcThis, q] (error *err) -> void
               {
                  q->remove_fd(rcThis->fd->Get(), rcThis.Get(), err);
               },
               err
            );
         }
         else
         {
            q->remove_fd(fd->Get(), this, err);
         }
      }
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
      if (p && fd->Valid())
      {
         if (!p->thread_helper.on_owning_thread())
         {
            Pointer<socket_wrapper> rcThis = this;

            p->thread_helper.enqueue_work(
               [rcThis, write] (error *err) -> void
               {
                  rcThis->set_needs_write(write, err);
               },
               err
            );

            return;
         }

         p->set_write(fd->Get(), write, this, err);
      }
   }
};

struct auto_reset_wrapper_base : public fd_wrapper_base, public pollster::auto_reset_signal
{
   bool repeat;

   auto_reset_wrapper_base() : repeat(false) {}

   void
   remove(error *err)
   {
      fd_wrapper_base::remove(err);
   }
};

class signal_block
{
   bool blocked;
   sigset_t sigset, old;
public:

   signal_block() : blocked(false)
   {
      sigemptyset(&sigset);
   }

   signal_block(const signal_block &p) = delete;

   void
   block(int sig, error *err)
   {
      sigaddset(&sigset, sig);

      if (pthread_sigmask(SIG_BLOCK, &sigset, &old))
         ERROR_SET(err, errno, errno);

      blocked = true;
   exit:;
   }

   sigset_t *
   get_sigset()
   {
      return &sigset;
   }

   ~signal_block()
   {
      if (blocked)
         pthread_sigmask(SIG_SETMASK, &old, nullptr);
   }
};

struct auto_reset_wrapper : public auto_reset_wrapper_base
{
   FileHandle writefd;

   void
   create(error *err)
   {
      int p[2];

      try
      {
         fd = std::make_shared<FileHandle>();
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      if (pipe(p))
         ERROR_SET(err, errno, errno);

      writefd = p[1];
      *fd = p[0];

      if (fcntl(fd->Get(), F_SETFL, O_NONBLOCK, 1))
         ERROR_SET(err, errno, errno);

      on_signal_impl = [this] (error *err) -> void
      {
         int r = 0;
         char buf[64];

         while ((r = read(fd->Get(), buf, sizeof(buf))) > 0);

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
      };
   exit:;
   }

   void
   signal(error *err)
   {
      char ch = 0;
      int r = 0;
      signal_block block;

      block.block(SIGPIPE, err);
      ERROR_CHECK(err);

      r = write(writefd.Get(), &ch, 1);
      if (r < 0)
         ERROR_SET(err, errno, errno);
      if (r != 1)
         ERROR_SET(err, unknown, "write: unexpected return value");
   exit:
      if (err->source == ERROR_SRC_ERRNO && err->code == EPIPE)
      {
         int sig = 0;
         do
         {
            if (sigwait(block.get_sigset(), &sig))
               ERROR_SET(err, errno, errno);
         } while (sig != SIGPIPE);
      }
   }
};

#if defined(USE_EVENTFD)
struct eventfd_wrapper : public auto_reset_wrapper_base
{
   void
   create(error *err)
   {
      try
      {
         fd = std::make_shared<FileHandle>();
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
      *fd = eventfd(0, 0);
      if (!fd->Valid())
         ERROR_SET(err, errno, errno);
      if (fcntl(fd->Get(), F_SETFL, O_NONBLOCK))
         ERROR_SET(err, errno, errno);

      on_signal_impl = [this] (error *err) -> void
      {
         uint64_t i;

         while (read(fd->Get(), &i, sizeof(i)) == sizeof(i))
         {
            if (on_signal)
            {
               on_signal(err);
               ERROR_CHECK(err);
            }

            if (!repeat)
            {
               remove(err); 
               goto exit;
            }
         }

         switch (errno)
         {
         case EAGAIN:
         case EINTR:
            break;
         default:
            ERROR_SET(err, errno, errno);
         }
      exit:;
      };
   exit:;
   }

   void
   signal(error *err)
   {
      uint64_t i = 1;
      if (write(fd->Get(), &i, sizeof(i)) != sizeof(i))
         ERROR_SET(err, errno, errno);
   exit:;
   }
};
#endif

} // end namespace

pollster::unix_backend::unix_backend()
{
   timer.thread_helper = &thread_helper;
}

void
pollster::unix_backend::add_socket(
   const std::shared_ptr<common::SocketHandle> &fd,
   bool write,
   std::function<void(socket_event *, error *)> initialize,
   socket_event **ev,
   error *err
)
{
   Pointer<socket_wrapper> e;

   New(e.GetAddressOf(), err);
   ERROR_CHECK(err);

   if (initialize)
   {
      initialize(e.Get(), err);
      ERROR_CHECK(err);
   }

   base_add_fd(fd->Get(), write, e.Get(), err);
   ERROR_CHECK(err);

   e->p = this;
   e->fd = fd;

exit:
   if (!ERROR_FAILED(err))
      *ev = e.Detach();
}

namespace {
template <typename T>
void
try_create_auto_reset(auto_reset_wrapper_base **ev, error *err)
{
   Pointer<T> e;

   if (*ev)
      goto exit;

   error_clear(err);

   New(e.GetAddressOf(), err);
   ERROR_CHECK(err);

   e->create(err);
   ERROR_CHECK(err);

   if (!ERROR_FAILED(err))
      *ev = e.Detach();
exit:;
}
} // end namespace

void
pollster::unix_backend::add_auto_reset_signal(
   bool repeating,
   std::function<void(auto_reset_signal *, error *)> initialize,
   auto_reset_signal **ev,
   error *err
)
{
   Pointer<auto_reset_wrapper_base> e;

#ifdef USE_EVENTFD
   try_create_auto_reset<eventfd_wrapper>(e.GetAddressOf(), err);
#endif
   try_create_auto_reset<auto_reset_wrapper>(e.GetAddressOf(), err);
   ERROR_CHECK(err);

   if (initialize)
   {
      initialize(e.Get(), err);
      ERROR_CHECK(err);
   }

   base_add_fd(e->fd->Get(), false, e.Get(), err);
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
   std::function<void(event *, error *)> initialize,
   event **ev,
   error *err
)
{
   timer.add(millis, repeating, initialize, ev, err);
}

void
pollster::unix_backend::base_exec(error *err)
{
   thread_helper_init args;
   args.backend = this;
   thread_helper.on_exec(&args, err);
}

void
pollster::unix_backend::base_add_fd(int fd, bool write_flag, event *object, error *err)
{
   if (thread_helper.on_owning_thread())
      add_fd(fd, write_flag, object, err);
   else
   {
      Pointer<unix_backend> rcThis = this;
      Pointer<event> rcEv = object;
      thread_helper.enqueue_work(
         [rcThis, fd, write_flag, rcEv] (error *err) -> void
         {
            rcThis->add_fd(fd, write_flag, rcEv.Get(), err);
         },
         err
      );
   }
}

