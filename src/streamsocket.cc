/*
 Copyright (C) 2019 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <common/c++/lock.h>

#if defined(_WINDOWS)
#include <pollster/win.h>
#endif

pollster::StreamSocket::StreamSocket(
   struct waiter *waiter_,
   std::shared_ptr<common::SocketHandle> fd_
)
: waiter(waiter_), fd(fd_), state(std::make_shared<SharedState>())
{
}

pollster::StreamSocket::StreamSocket(
   std::function<void(const void *buf, int len, error *err)> writeFn_
)
: writeFn(writeFn_)
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
            if (on_error)
               on_error(err);
            if (fd->Valid() && on_closed)
            {
               error_clear(err);
               on_closed(err);
            }
         }
      );
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }
exit:
   if (ERROR_FAILED(&err) && on_error)
   {
      on_error(&err);
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

   set_nonblock(fd->Get(), true, &err);
   ERROR_CHECK(&err);

   AttachSocket(&err);
   ERROR_CHECK(&err);

exit:
   if (ERROR_FAILED(&err))
   {
      fd->Reset();

      if (on_error)
         on_error(&err);
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
         std::function<void(const void*, int, error *)> newWriter;
         bool needLock;
         std::vector<unsigned char> pending;
         std::mutex lock;

         writeState() : needLock(true) {}
      };
      auto writeBuf = std::make_shared<writeState>();
      writeFn = [writeBuf] (const void *buf, int len, error *err) -> void
      {
         common::locker l;

         if (writeBuf->needLock)
            l.acquire(writeBuf->lock);

         // Do we have a new writer?  If so, re-do.
         //
         if (writeBuf->newWriter)
         {
            l.release();
            writeBuf->newWriter(buf, len, err);
            return;
         }

         // Nope, buffer the data.
         //
         auto &pending = writeBuf->pending;
         try
         {
            pending.insert(pending.end(), (const char*)buf, (const char*)buf+len);
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
            std::function<void(const void *, int, error*)> newWriter;

            windows::BindLegacyAfUnixClient(waiter.Get(), client, newWriter, on_recv, on_closed, on_error, err);
            ERROR_CHECK(err);

            // Get the lock before flushing buffered stuff and re-assigning writer.
            //
            l.acquire(writeBuf->lock);

            if (writeBuf->pending.size())
            {
               newWriter(writeBuf->pending.data(), writeBuf->pending.size(), err);
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

static void
CheckIoError(int &r, error *err)
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

void
pollster::StreamSocket::AttachSocket(error *err)
{
   try
   {
      common::locker l;
      auto fd = this->fd;
      auto state = this->state;
      auto on_recv = this->on_recv;
      auto on_closed = this->on_closed;
      l.acquire(state->writeLock);

      waiter->add_socket(
         fd,
         state->writeBuffer.size() ? true : false,
         [fd, state, on_recv, on_closed] (socket_event *sev, error *err) -> void
         {
            try
            {
               sev->on_signal = [fd, state, sev, on_recv, on_closed] (error *err) -> void
               {
                  char buf[4096];
                  int r = 0;
                  common::locker l;
                  auto &writeBuffer = state->writeBuffer;

                  l.acquire(state->writeLock);
                  while (writeBuffer.size() && (r = send(fd->Get(), writeBuffer.data(), writeBuffer.size(), 0)) > 0)
                  {
                     writeBuffer.erase(writeBuffer.begin(), writeBuffer.begin() + r);
                     if (!writeBuffer.size())
                     {
                        sev->set_needs_write(false, err);
                        ERROR_CHECK(err);
                     }
                  }
                  l.release();

                  CheckIoError(r, err);
                  ERROR_CHECK(err);

                  while ((r = recv(fd->Get(), buf, sizeof(buf), 0)) > 0)
                  {
                     on_recv(buf, r, err);
                     ERROR_CHECK(err);
                  }

                  CheckIoError(r, err);
                  ERROR_CHECK(err);

                  if (r == 0)
                  {
                     error innerError;
                     common::Pointer<pollster::socket_event> rc;

                     if (on_closed)
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
pollster::StreamSocket::Write(const void *buf, int len)
{
   error err;
   common::locker l;
   bool was_empty = false;

   if (writeFn)
   {
      writeFn(buf, len, &err);
      ERROR_CHECK(&err);
      goto exit;
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
exit:
   l.release();
   if (ERROR_FAILED(&err))
   {
      if (on_error)
         on_error(&err);
      if (sev.Get())
      {
         error innerError;
         sev->remove(&innerError);
      }
   }
}
