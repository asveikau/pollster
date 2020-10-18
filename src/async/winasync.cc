/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/win.h>
#include <common/misc.h>

namespace
{
   struct OverlappedSubclass : public OVERLAPPED
   {
      std::function<void (error *)> on_error;
      std::function<void (DWORD, OVERLAPPED*, error *)> on_result;
      common::Pointer<pollster::auto_reset_signal> ev;

      OverlappedSubclass()
      {
         Internal = InternalHigh = 0;
         Offset = OffsetHigh = 0;
         hEvent = nullptr;
      }

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
   const uint64_t *offset_opt,
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

   if (offset_opt)
   {
      LARGE_INTEGER off;

      off.QuadPart = *offset_opt;
      ol->Offset = off.LowPart;
      ol->OffsetHigh = off.HighPart;
   }

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

#if defined(_M_ARM64) || defined(_M_AMD64) || defined(_M_IA64)
template<typename T1, typename T2>
struct ReadWriteHelper : public std::enable_shared_from_this<ReadWriteHelper<T1, T2>>
{
   common::Pointer<pollster::waiter> w;
   std::shared_ptr<common::FileHandle> file;
   T1 op;
   T2 buffer;
   size_t remainingLen;
   size_t totalLen;
   uint64_t offsetStorage;
   uint64_t *offset;

   std::function<void(error *)> on_error;
   std::function<void(size_t, error *)> on_result;

   ReadWriteHelper(
      pollster::waiter *w_,
      const std::shared_ptr<common::FileHandle> &file_,
      const T1 & op_,
      const uint64_t *offset_,
      T2 &buffer_,
      size_t len
   )
   : w(w_), file(file_), op(op_), buffer(buffer_), remainingLen(len), totalLen(0)
   {
      if (offset_)
      {
         offsetStorage = *offset_;
         offset = &offsetStorage;
      }
      else
      {
         offsetStorage = 0;
         offset = nullptr;
      }
   }

   DWORD
   GetCurrentIoSize()
   {
      const size_t dwordMax = ((DWORD)~0U);
      return (DWORD)(MIN(dwordMax, remainingLen));
   }

   void
   PerformIo(error *err)
   {
      auto rc = shared_from_this();

      ReadWrite(
         w.Get(),
         file,
         op,
         offset,
         buffer,
         GetCurrentIoSize(),
         [rc] (error *err) -> void
         {
            rc->OnError(err);
         },
         [rc] (DWORD res, error *err) -> void
         {
            rc->OnResult(res, err);
         }
      );
   }

   void
   OnError(error *err)
   {
      if (totalLen)
      {
         // XXX we discard error info here
         error_clear(err);
         on_result(totalLen, err);
      }
      else
      {
         on_error(err);
      }
   }

   void
   OnResult(DWORD res, error *err)
   {
      if (res)
      {
         bool partial = (res < GetCurrentIoSize());

         totalLen += res;
         remainingLen -= res;
         buffer = (T2*)((char*)buffer + res);
         offsetStorage += res;

         if (remainingLen && !partial)
         {
            PerformIo(err);
            return;
         }
      }
      on_result(totalLen, err);
   }
};

template<typename T1, typename T2>
void
ReadWrite(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   T1 op,
   uint64_t *offset_opt,
   T2 buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
   if (len <= ((DWORD)~0U))
   {
      ReadWrite(
         w, file, op, offset_opt, buffer, (DWORD)len, on_error,
         [on_result] (DWORD res, error *err) ->  void
         {
            on_result(res, err);
         }
      );
   }
   else
   {
      error err;
      std::shared_ptr<ReadWriteHelper<T1, T2>> p;

      try
      {
         p = std::make_shared<ReadWriteHelper<T1, T2>>(w, file, op, offset_opt, buffer, len);
         p->on_result = on_result;
         p->on_error = on_error;
      }
      catch (std::bad_alloc)
      {
         error_set_nomem(&err);
         on_error(&err);
         return;
      }

      p->PerformIo(&err);
      if (ERROR_FAILED(&err))
         p->on_error(&err);
   }
}
#endif

} // end namespace

void
pollster::windows::ReadFileAsync(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const uint64_t *offset_opt,
   void *buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
   ReadWrite(w, file, ReadFileEx, offset_opt, buffer, len, on_error, on_result);
}

void
pollster::windows::WriteFileAsync(
   pollster::waiter *w,
   const std::shared_ptr<common::FileHandle> &file,
   const uint64_t *offset_opt,
   const void *buffer,
   size_t len,
   const std::function<void(error *)> &on_error,
   const std::function<void(size_t, error *)> &on_result
)
{
   ReadWrite(w, file, WriteFileEx, offset_opt, buffer, len, on_error, on_result);
}