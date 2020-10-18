/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/pollster.h>
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
   common::Pointer<pollster::sigev_extif> sigEvExt;

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
      [cb, on_result] (error *err) -> void
      {
         ssize_t r = aio_return(cb.get());
         if (r < 0)
            ERROR_SET(err, errno, errno);
         on_result(r, err);
      exit:;
      },
      on_error ?
         [cb, on_error] (error *err) -> void
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
   }
}

bool
ShouldAttemptAio(int fd)
{
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

   if (on_error)
   {
      error err;
      error_set_unknown(&err, "TODO: implement aio fallback");
      on_error(&err);
   }
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

   if (on_error)
   {
      error err;
      error_set_unknown(&err, "TODO: implement aio fallback");
      on_error(&err);
   }
}
