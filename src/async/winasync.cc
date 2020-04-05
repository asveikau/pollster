/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/win.h>

namespace
{
   struct OverlappedSubclass : public OVERLAPPED
   {
      std::function<void (error *)> on_error;
      std::function<void (DWORD, OVERLAPPED*, error *)> on_result;
      common::Pointer<pollster::auto_reset_signal> ev;

      ~OverlappedSubclass()
      {
         if (ev.Get())
         {
            error err;
            ev->remove(&err);
         }
      }

      static VOID CALLBACK
      CompletionCallback(DWORD errorCode, DWORD nb, OVERLAPPED *ol)
      {
         auto olSub = reinterpret_cast<OverlappedSubclass*>(ol);
         error err;

         if (errorCode)
         {
            if (olSub->on_error)
            {
               error_set_win32(&err, errorCode);
               olSub->on_error(&err);
            }
         }
         else
         {
            olSub->on_result(nb, ol, &err);
            if (ERROR_FAILED(&err) && olSub->on_error)
            {
               olSub->on_error(&err);
            }
         }
         delete olSub;
      }
   };
}

void
pollster::windows::CreateOverlapped(
   waiter *w,
   const std::function<void (error *)> &on_error,
   const std::function<void (DWORD, OVERLAPPED*, error *)> &on_result,
   OVERLAPPED **res,
   LPOVERLAPPED_COMPLETION_ROUTINE *fn,
   error *err
)
{
   auto r = new (std::nothrow) OverlappedSubclass();
   if (!r)
      ERROR_SET(err, nomem);
   try
   {
      r->on_error = std::move(on_error);
      r->on_result = std::move(on_result);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   if (fn)
   {
      *fn = &OverlappedSubclass::CompletionCallback;
   }
   else
   {
      common::Pointer<pollster::waiter> wp;
      auto &ev = r->ev;

      if (!w)
      {
         pollster::get_common_queue(wp.GetAddressOf(), err);
         ERROR_CHECK(err);
         w = wp.Get();
      }

      w->add_auto_reset_signal(
         true, // XXX - making repeatable prevents double-remove.
         ev.GetAddressOf(),
         err
      );
      ERROR_CHECK(err);

      r->hEvent = ev->get_handle();

      ev->on_signal = [r] (error *err) -> void
      {
         OverlappedSubclass::CompletionCallback(r->Internal, r->InternalHigh, r);
      };
   }
exit:
   if (ERROR_FAILED(err) && r)
   {
      delete r;
      r = nullptr;
   }
   *res = r;
   if (*res)
      memset(*res, 0, sizeof(res));
}

void
pollster::windows::FreeOverlapped(OVERLAPPED *ol)
{
   if (ol)
   {
      auto p = (OverlappedSubclass*)ol;
      delete p;
   }
}

namespace {

template<typename T1, typename T2>
void
ReadWrite(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   T1 op,
   T2 buffer,
   DWORD len,
   const std::function<void(error *)> &on_error,
   const std::function<void(DWORD, error *)> &on_result
)
{
   OVERLAPPED *ol = nullptr;
   LPOVERLAPPED_COMPLETION_ROUTINE fn = nullptr;
   error err;

   pollster::windows::CreateOverlapped(
      w,
      on_error,
      [on_result] (DWORD res, OVERLAPPED *ol, error *err) -> void
      {
         on_result(res, err);
      },
      &ol,
      &fn,
      &err
   );
   ERROR_CHECK(&err);

   if (!op(file->Get(), buffer, len, ol, fn))
   {
      DWORD error = GetLastError();

      switch (error)
      {
      case ERROR_IO_PENDING:
         ol = nullptr;
         break;
      default:
         ERROR_SET(&err, win32, error);
      }
   }
   else
   {
      // It would make sense for this case to represent synchronous completion
      // and for ol->InternalHigh to be the result, but for ReadFileEx/WriteFileEx
      // it seems it does not.
      //
      ol = nullptr;
   }
exit:
   pollster::windows::FreeOverlapped(ol);
   if (ERROR_FAILED(&err) && on_error)
      on_error(&err);
}

} // end namespace

void
pollster::windows::ReadFileAsync(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   void *buffer,
   DWORD len,
   const std::function<void(error *)> &on_error,
   const std::function<void(DWORD, error *)> &on_result
)
{
   ReadWrite(w, file, ReadFileEx, buffer, len, on_error, on_result);
}

void
pollster::windows::WriteFileAsync(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const void *buffer,
   DWORD len,
   const std::function<void(error *)> &on_error,
   const std::function<void(DWORD, error *)> &on_result
)
{
   ReadWrite(w, file, WriteFileEx, buffer, len, on_error, on_result);
}