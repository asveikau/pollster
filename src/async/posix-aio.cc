/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/pollster.h>
#include <common/c++/worker.h>
#include <common/path.h>
#include <string.h>

#if defined(HAVE_AIO)
#include <aio.h>

namespace {

template <typename T, typename Func>
void
PosixAioReadWrite(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   int opcode,
   Func func,
   const uint64_t *offset_opt,
   T buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
   error err;
   std::shared_ptr<aiocb> cb;
   common::Pointer<pollster::waiter> wp;
   common::Pointer<pollster::sigev_extif> sigEvExt;

   if (!w)
   {
      pollster::get_common_queue(wp.GetAddressOf(), &err);
      ERROR_CHECK(&err);
      w = wp.Get();
   }

   *sigEvExt.GetAddressOf() = (pollster::sigev_extif*)w->get_interface(pollster::SigEvent, &err);
   if (!sigEvExt.Get())
      ERROR_SET(&err, unknown, "No sigevent support");

   try
   {
      cb = std::make_shared<aiocb>();
   }
   catch (const std::bad_alloc&)
   {
      ERROR_SET(&err, nomem);
   }

   memset(cb.get(), 0, sizeof(*cb.get()));

   cb->aio_fildes = file->Get();
   cb->aio_buf = (volatile void*)buffer;
   cb->aio_nbytes = len;  // TODO: truncate for ssize_t
   cb->aio_lio_opcode = opcode;
   if (offset_opt)
      cb->aio_offset = *offset_opt;

   sigEvExt->wrap_sigev(
      &cb->aio_sigevent,
      [file, cb, on_result] (error *err) -> void
      {
         ssize_t r = aio_return(cb.get());
         if (r < 0)
            ERROR_SET(err, errno, errno);
         on_result(r, err);
      exit:;
      },
      on_error ?
         [file, cb, on_error] (error *err) -> void
         {
            on_error(err);
         } : std::function<void(error*)>(),
      &err
   );
   ERROR_CHECK(&err);

   if (func(cb.get()))
      ERROR_SET(&err, errno, errno);

exit:
   if (ERROR_FAILED(&err))
   {
      if (on_error)
         on_error(&err);

      if (sigEvExt.Get())
         sigEvExt->remove_sigev(&cb->aio_sigevent);
   }
}

bool
ShouldAttemptAio(int fd)
{
   return false;
#if defined(__FreeBSD__)
   // FreeBSD can't handle AIO for network filesystems
   // XXX - maybe it's expensive always adding an extra syscall here.
   error err;
   return !fd_is_remote(fd, &err);
#else
   return true;
#endif
}

} // end namespace

#endif

static common::WorkerThread
fallbackWorker;

namespace {
template<typename T>
void
PerformOp(
   pollster::waiter *w,
   T fn,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
   error err;

   auto rc = common::Pointer<pollster::waiter>(w);
   if (!rc.Get())
   {
      pollster::get_common_queue(rc.GetAddressOf(), &err);
      if (ERROR_FAILED(&err))
         return;
   }
   auto exec = [rc, on_error] (const std::function<void(error *err)> &fn, error *err) -> void
   {
      common::Pointer<pollster::auto_reset_signal> ev;

      rc->add_auto_reset_signal(
         false,
         [&] (pollster::auto_reset_signal *ev, error *err) -> void
         {
            ev->on_signal = fn;
            ev->on_error = on_error;
         },
         ev.GetAddressOf(),
         err
      );
      if (!ERROR_FAILED(err))
         ev->signal(err);
   };

   fallbackWorker.Schedule(
      [exec, fn, on_result, on_error] (error *err) -> void
      {
         fn(
            [exec, on_result] (size_t r, error *err) -> void
            {
               exec(
                  [r, on_result] (error *err) -> void
                  {
                     on_result(r, err);
                  },
                  err
               );
            },
            err
         );
         if (ERROR_FAILED(err) && on_error)
         {
            on_error(err);
         }
      },
      false,
      &err
   );

   if (ERROR_FAILED(&err) && on_error)
      on_error(&err);
}

} // end namespace

void
pollster::ReadFileAsync(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const uint64_t *offset_opt,
   void *buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
#ifdef HAVE_AIO
   if (ShouldAttemptAio(file->Get()))
   {
      PosixAioReadWrite(w, file, LIO_READ, aio_read, offset_opt, buffer, len, on_error, on_result);
      return;
   }
#endif

   int64_t off = offset_opt ? *offset_opt : -1;

   PerformOp(
      w,
      [file, off, buffer, len] (const std::function<void(size_t, error *)> &on_result, error *err) -> void
      {
         ssize_t r = 0;
         if (off >= 0)
            r = pread(file->Get(), buffer, len, off);
         else
            r = read(file->Get(), buffer, len);
         if (r < 0)
            error_set_errno(err, errno);
         else
            on_result(r, err);
      },
      on_error,
      on_result
   );
}

void
pollster::WriteFileAsync(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const uint64_t *offset_opt,
   const void *buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
#ifdef HAVE_AIO
   if (ShouldAttemptAio(file->Get()))
   {
      PosixAioReadWrite(w, file, LIO_WRITE, aio_write, offset_opt, buffer, len, on_error, on_result);
      return;
   }
#endif

   int64_t off = offset_opt ? *offset_opt : -1;

   PerformOp(
      w,
      [file, off, buffer, len] (const std::function<void(size_t, error *)> &on_result, error *err) -> void
      {
         ssize_t r = 0;
         if (off >= 0)
            r = pwrite(file->Get(), buffer, len, off);
         else
            r = write(file->Get(), buffer, len);
         if (r < 0)
            error_set_errno(err, errno);
         else
            on_result(r, err);
      },
      on_error,
      on_result
   );
}
