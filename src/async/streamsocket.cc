/*
 Copyright (C) 2019-2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <common/c++/lock.h>
#include <common/size.h>

#if defined(_WINDOWS)
#include <pollster/win.h>
#endif

pollster::StreamSocket::StreamSocket(
   struct waiter *waiter_,
   std::shared_ptr<common::SocketHandle> fd_
)
: waiter(waiter_), fd(fd_), state(std::make_shared<SharedState>()), filterEof(false)
{
}

pollster::StreamSocket::StreamSocket(
   const WriteFunction &writeFn_
)
: writeFn(writeFn_), filterEof(false)
{
}

pollster::StreamSocket::~StreamSocket()
{
   if (sev.Get())
   {
      error err;
      sev->remove(&err);
   }
}

void
pollster::StreamSocket::Connect(const char *host, const char *service)
{
   error err;

   if ((fd.get() && fd->Valid()) || writeFn)
      ERROR_SET(&err, unknown, "Already bound to socket");

   if (!waiter.Get())
   {
      get_common_queue(waiter.GetAddressOf(), &err);
      ERROR_CHECK(&err);
   }

   try
   {
      ConnectAsync(
         waiter.Get(),
         host,
         service,
         [this] (pollster::ConnectAsyncStatus state, const char *arg, error *err) -> void
         {
            if (on_connect_progress)
               on_connect_progress(state, arg, err);
         },
         [this] (const std::shared_ptr<common::SocketHandle> &fd, error *err) -> void
         {
            this->fd = fd;
            AttachSocket(err);
            ERROR_CHECK(err);
         exit:;
         },
         [this] (error *err)
         {
            OnAsyncError(err);
            if (fd->Valid())
            {
               error_clear(err);
               OnClosed(err);
            }
         }
      );
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }
exit:
   if (ERROR_FAILED(&err))
   {
      OnAsyncError(&err);
   }
}

void
pollster::StreamSocket::ConnectUnixDomain(const char *path)
{
   error err;
   struct sockaddr_un un = {0};
   struct sockaddr *sa = (struct sockaddr*)&un;

   if ((fd.get() && fd->Valid()) || writeFn)
      ERROR_SET(&err, unknown, "Already bound to socket");

   if (!waiter.Get())
   {
      get_common_queue(waiter.GetAddressOf(), &err);
      ERROR_CHECK(&err);
   }

   socket_startup(&err);
   ERROR_CHECK(&err);

   sockaddr_un_set(&un, path, &err);
   ERROR_CHECK(&err);

   *fd = socket(PF_UNIX, SOCK_STREAM, 0);
   if (!fd->Valid())
   {
#if defined(_WINDOWS)
      goto winFallback;
#endif
      ERROR_SET(&err, socket);
   }

#if defined(_WINDOWS) && defined(TEST_LEGACY_UNIX_SOCKET)
   goto winFallback;
#endif

   if (connect(fd->Get(), sa, socklen(sa)))
   {
#if defined(_WINDOWS)
      if (GetLastError() == WSAEINVAL)
         goto winFallback;
#endif
      ERROR_SET(&err, socket);
   }

   if (on_connect_progress)
   {
      on_connect_progress(ConnectAsyncStatus::Connected, nullptr, &err);
      ERROR_CHECK(&err);
   }

   set_nonblock(fd->Get(), true, &err);
   ERROR_CHECK(&err);

   AttachSocket(&err);
   ERROR_CHECK(&err);

exit:
   if (ERROR_FAILED(&err))
   {
      fd->Reset();

      OnAsyncError(&err);
   }
   return;
#if defined(_WINDOWS)
winFallback:
   fd->Reset();

   try
   {
      auto rcThis = shared_from_this();

      //
      // Buffer writes that happen before we have the new writeFn.
      //

      struct writeState
      {
         WriteFunction newWriter;
         bool needLock;
         std::vector<unsigned char> pending;
         std::vector<std::function<void(error*)>> pendingCallbacks;
         std::mutex lock;

         writeState() : needLock(true) {}
      };
      auto writeBuf = std::make_shared<writeState>();
      writeFn = [writeBuf] (const void *buf, size_t len, const std::function<void(error*)> &onComplete, error *err) -> void
      {
         common::locker l;

         if (writeBuf->needLock)
            l.acquire(writeBuf->lock);

         // Do we have a new writer?  If so, re-do.
         //
         if (writeBuf->newWriter)
         {
            l.release();
            writeBuf->newWriter(buf, len, onComplete, err);
            return;
         }

         // Nope, buffer the data.
         //
         auto &pending = writeBuf->pending;
         try
         {
            pending.insert(pending.end(), (const char*)buf, (const char*)buf+len);
            if (onComplete)
               writeBuf->pendingCallbacks.push_back(onComplete);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      exit:;
      };
      windows::CreateLegacyAfUnixClient(
         waiter.Get(),
         &un,
         [this, rcThis, writeBuf] (const std::shared_ptr<common::FileHandle> &client, error *err) -> void
         {
            common::locker l;

            // Assign new writer into temp.
            //
            WriteFunction newWriter;

            auto weak = std::weak_ptr<pollster::StreamSocket>(shared_from_this());

            auto on_recv = [weak] (const void *buf, size_t len, error *err) -> void
            {
               auto self = weak.lock();
               if (self)
                  self->OnBytesReceived(buf, len, err);
               else
                  error_set_unknown(err, "Read performed on abandoned socket");
            };

            auto on_closed = [weak] (error *err) -> void
            {
               auto self = weak.lock();
               if (self)
                  self->OnClosed(err);
            };

            auto on_error = [weak] (error *err) -> void
            {
               auto self = weak.lock();
               if (self)
                  self->OnAsyncError(err);
            };

            if (on_connect_progress)
            {
               on_connect_progress(ConnectAsyncStatus::Connected, nullptr, err);
               ERROR_CHECK(err);
            }

            windows::BindLegacyAfUnixClient(waiter.Get(), client, newWriter, on_recv, on_closed, on_error, err);
            ERROR_CHECK(err);

            // Get the lock before flushing buffered stuff and re-assigning writer.
            //
            l.acquire(writeBuf->lock);

            if (writeBuf->pending.size())
            {
               newWriter(
                  writeBuf->pending.data(),
                  writeBuf->pending.size(),
                  writeBuf->pendingCallbacks.size() ?
                     [writeBuf] (error *err) -> void
                     {
                        for (auto &cb : writeBuf->pendingCallbacks)
                        {
                           cb(err);
                           ERROR_CHECK(err);
                        }
                     exit:
                        writeBuf->pendingCallbacks.resize(0);
                        writeBuf->pendingCallbacks.shrink_to_fit();
                     } : std::function<void(error*)>(),
                  err
               );
               ERROR_CHECK(err);

               writeBuf->pending.resize(0);
               writeBuf->pending.shrink_to_fit();
            }

            writeBuf->newWriter = std::move(newWriter);

            l.release();
            writeBuf->needLock = false;
         exit:;
         },
         &err
      );
      ERROR_CHECK(&err);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }
#endif
}

namespace {

void
CheckIoError(pollster::sendrecv_retval &r, error *err)
{
   if (r < 0)
   {
      switch (SOCKET_LASTERROR)
      {
#if !defined(_WINDOWS)
      case SOCK_ERROR(EAGAIN):
#endif
#if defined(_WINDOWS) || (SOCK_ERROR(EAGAIN) != SOCK_ERROR(EWOULDBLOCK))
      case SOCK_ERROR(EWOULDBLOCK):
#endif
         break;
      default:
         ERROR_SET(err, socket);
      }
   }
exit:;
}

} // end namespace

void
pollster::StreamSocket::AttachSocket(error *err)
{
   try
   {
      common::locker l;
      auto &fd = this->fd;
      auto &state = this->state;

      auto weak = std::weak_ptr<pollster::StreamSocket>(shared_from_this());

      auto on_recv = [weak] (const void *buf, size_t len, error *err) -> void
      {
         auto self = weak.lock();
         if (self)
            self->OnBytesReceived(buf, len, err);
      };

      auto on_error = [weak] (error *err) -> void
      {
         auto self = weak.lock();
         if (self)
            self->OnAsyncError(err);
      };

      auto on_closed = [weak] (error *err) -> void
      {
         auto self = weak.lock();
         if (self)
            self->OnClosed(err);
      };

      l.acquire(state->writeLock);

      waiter->add_socket(
         fd,
         state->writeBuffer.size() ? true : false,
         [fd, state, on_recv, on_error, on_closed, weak] (socket_event *sev, error *err) -> void
         {
            try
            {
               sev->on_error = on_error;

               sev->on_signal = [fd, state, sev, on_recv, on_closed, weak] (error *err) -> void
               {
                  char buf[4096];
                  pollster::sendrecv_retval r = 0;
                  common::locker l;
                  auto &writeBuffer = state->writeBuffer;
                  size_t written = 0;
                  WriteCompletionNode *first = nullptr;
                  WriteCompletionNode *n = nullptr;
                  bool filterEof = false;

                  l.acquire(state->writeLock);

                  while (writeBuffer.size() && (r = send(fd->Get(), writeBuffer.data(), MIN(SENDRECV_MAX, writeBuffer.size()), 0)) > 0)
                  {
                     written += r;
                     writeBuffer.erase(writeBuffer.begin(), writeBuffer.begin() + r);

                     if (!writeBuffer.size())
                     {
                        sev->set_needs_write(false, err);
                        ERROR_CHECK(err);
                     }
                  }

                  for (first = n = state->completionCallbacks; n && written; )
                  {
                     auto sub = MIN(n->len, written);
                     n->len -= sub;
                     written -= sub;
                     if (n->len)
                     {
                        state->completionCallbacks = n;
                        break;
                     }
                     n = state->completionCallbacks = n->next;
                  }
                  if (first && first->len)
                     first = nullptr;

                  l.release();

                  while (first && first != state->completionCallbacks)
                  {
                     auto next = first->next;
                     if (!ERROR_FAILED(err))
                        first->callback(err);
                     delete first;
                     first = next;
                  }
                  ERROR_CHECK(err);

                  CheckIoError(r, err);
                  ERROR_CHECK(err);

                  while ((r = recv(fd->Get(), buf, sizeof(buf), 0)) > 0)
                  {
                     on_recv(buf, r, err);
                     ERROR_CHECK(err);
                  }

                  CheckIoError(r, err);
                  ERROR_CHECK(err);

                  if (r != 0)
                  {
                     auto self = weak.lock();
                     if (self.get())
                        filterEof = self->filterEof;
                  }

                  if (r == 0 || filterEof)
                  {
                     error innerError;
                     common::Pointer<pollster::socket_event> rc;

#if 0 // XXX made sense when this was a std::function
                     if (on_closed)
#endif
                     {
                        rc = sev;
                        on_closed(err);
                     }
                     sev->remove(&innerError);
                     ERROR_CHECK(err);
                  }
               exit:;
               };
            } catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }
         exit:;
         },
         sev.GetAddressOf(),
         err
      );
      ERROR_CHECK(err);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}

void
pollster::StreamSocket::Write(const void *buf, size_t len, const std::function<void(error*)> &onComplete)
{
   error err;

   if (!len)
   {
      if (onComplete)
         onComplete(&err);
      goto exit;
   }

   if (CheckFilter(&err))
   {
      filter->Write(buf, len, onComplete);
      return;
   }
   ERROR_CHECK(&err);

   OnWriteRequested(buf, len, onComplete);
exit:
   if (ERROR_FAILED(&err))
   {
      OnAsyncError(&err);
      if (sev.Get())
      {
         error innerError;
         sev->remove(&innerError);
      }
   }
}

void
pollster::StreamSocket::OnBytesReceived(const void *buf, size_t len, error *err)
{
   if (CheckFilter(err))
   {
      filter->OnBytesReceived(buf, len, err);
      return;
   }
   ERROR_CHECK(err);

   on_recv(buf, len, err);
   ERROR_CHECK(err);
exit:;
}

void
pollster::StreamSocket::OnAsyncError(error *err)
{
#if 0 // This would wind up as a circular call
   error innerErr;

   if (CheckFilter(&innerErr))
   {
      filter->Events->OnAsyncError(err);
   }
#endif

   if (on_error)
      on_error(err);
}

void
pollster::StreamSocket::OnClosed(error *err)
{
   if (CheckFilter(err))
   {
      filter->OnEof();
   }
   ERROR_CHECK(err);
   if (on_closed)
      on_closed(err);
exit:;
}

namespace {

template<typename OnError, typename OnWrite, typename OnRecv, typename OnClose>
class CallbackFilterEvents : public pollster::FilterEvents
{
   OnError onError;
   OnWrite onWrite;
   OnRecv onRecv;
   OnClose onClose;
public:
   CallbackFilterEvents(
      const OnError &onError_,
      const OnWrite &onWrite_,
      const OnRecv &onRecv_,
      const OnClose &onClose_
   ) : onError(onError_),
       onWrite(onWrite_),
       onRecv(onRecv_),
       onClose(onClose_)
   {}

   void
   OnAsyncError(error *err)
   {
      onError(err);
   }

   void
   OnBytesToWrite(const void *buf, size_t len, const std::function<void(error*)> &onComplete)
   {
      onWrite(buf, len, onComplete);
   }

   void
   OnBytesReceived(const void *buf, size_t len, error *err)
   {
      onRecv(buf, len, err);
   }

   void
   OnClosed(error *err)
   {
      onClose(err);
   }
};

template<typename OnError, typename OnWrite, typename OnRecv, typename OnClosed>
std::shared_ptr<pollster::FilterEvents>
CreateFilterEvents(
   const OnError &onError,
   const OnWrite &onWrite,
   const OnRecv &onRecv,
   const OnClosed &onClosed,
   error *err
)
{
   std::shared_ptr<pollster::FilterEvents> r;
   pollster::FilterEvents *rp = nullptr;
   try
   {
      rp = new CallbackFilterEvents<OnError, OnWrite, OnRecv, OnClosed>(onError, onWrite, onRecv, onClosed);
      r = std::shared_ptr<pollster::FilterEvents>(rp);
      rp = nullptr;
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:
   if (rp)
      delete rp;
   return r;
}

} // end namepace

bool
pollster::StreamSocket::CheckFilter(error *err)
{
   bool r = false;
   if ((r = filter.get()))
   {
      if (!filter->Events.get())
      {
         auto weak = std::weak_ptr<pollster::StreamSocket>(shared_from_this());

         filter->Events = CreateFilterEvents(
            // onError:
            [weak] (error *err) -> void
            {
               auto self = weak.lock();
               if (self)
               {
                  self->OnAsyncError(err);
                  if (self->sev.Get())
                  {
                     error innerError;
                     self->sev->remove(&innerError);
                  }
               }
            },
            // onWrite:
            [weak] (const void *buf, size_t len, const std::function<void(error*)> &onComplete) -> void
            {
               auto self = weak.lock();
               if (self)
                  self->OnWriteRequested(buf, len, onComplete);
            },
            // onRecv:
            [weak] (const void *buf, size_t len, error *err) -> void
            {
               auto self = weak.lock();
               if (self)
                  self->on_recv(buf, len, err);
               else
                  error_set_unknown(err, "Read performed on abandoned socket");
            },
            // onClosed:
            [weak] (error *err) -> void
            {
               auto self = weak.lock();
               if (self)
                  self->filterEof = true;
            },
            err
         );
         ERROR_CHECK(err);

         filter->OnEventsInitialized(err);
         ERROR_CHECK(err);
      }
   }
exit:
   return r && !ERROR_FAILED(err);
}

void
pollster::StreamSocket::OnWriteRequested(const void *buf, size_t len, const std::function<void(error*)> &onComplete)
{
   error err;
   common::locker l;
   bool was_empty = false;
   WriteCompletionNode *qn = nullptr;

   if (!len)
   {
      if (onComplete)
         onComplete(&err);
      goto exit;
   }

   if (writeFn)
   {
      writeFn(buf, len, onComplete, &err);
      ERROR_CHECK(&err);
      goto exit;
   }

   if (onComplete)
   {
      qn = new (std::nothrow) WriteCompletionNode();
      if (!qn)
         ERROR_SET(&err, nomem);
      qn->callback = std::move(onComplete);
   }

   l.acquire(state->writeLock);
   was_empty = !state->writeBuffer.size();

   try
   {
      state->writeBuffer.insert(state->writeBuffer.end(), (const char*)buf, (const char*)buf+len);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

   if (was_empty && sev.Get())
   {
      sev->set_needs_write(true, &err);
      ERROR_CHECK(&err);
   }

   if (qn)
   {
      WriteCompletionNode **prev = &state->completionCallbacks;
      WriteCompletionNode *n = *prev;

      qn->len = state->writeBuffer.size();

      while (n && qn->len > n->len)
      {
         qn->len -= n->len;
         prev = &n->next;
         n = *prev;
      }

      qn->next = *prev;
      *prev = qn;
      qn = nullptr;
   }

exit:
   l.release();
   if (qn)
      delete qn;
   if (ERROR_FAILED(&err))
   {
      OnAsyncError(&err);
      if (sev.Get())
      {
         error innerError;
         sev->remove(&innerError);
      }
   }
}

pollster::StreamSocket::SharedState::~SharedState()
{
   auto p = completionCallbacks;
   completionCallbacks = nullptr;

   while (p)
   {
      auto q = p->next;
      delete p;
      p = q;
   }
}