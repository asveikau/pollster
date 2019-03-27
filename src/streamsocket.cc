#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <common/c++/lock.h>

void
pollster::StreamSocket::Connect(const char *host, const char *service)
{
   error err;

   if (fd->Valid())
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

static void
CheckIoError(int &r, error *err)
{
   if (r < 0)
   {
      switch (SOCKET_LASTERROR)
      {
      case SOCK_ERROR(EAGAIN):
#if (SOCK_ERROR(EAGAIN) != SOCK_ERROR(EWOULDBLOCK))
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
   common::locker l;
   l.acquire(writeLock);

   waiter->add_socket(
      fd,
      writeBuffer.size() ? true : false,
      [this] (socket_event *sevWeak, error *err) -> void
      {
         sevWeak->on_signal = [this] (error *err) -> void
         {
            char buf[4096];
            int r = 0;
            common::locker l;

            l.acquire(writeLock);
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

               if (on_closed)
                  on_closed(err);
               sev->remove(&innerError);
               ERROR_CHECK(err);
            }
         exit:;
         };
      },
      sev.GetAddressOf(),
      err
   );
   ERROR_CHECK(err);
exit:;
}

void
pollster::StreamSocket::Write(const void *buf, int len)
{
   error err;
   common::locker l;
   l.acquire(writeLock);
   bool was_empty = !writeBuffer.size();

   try
   {
      writeBuffer.insert(writeBuffer.end(), (const unsigned char*)buf, (const unsigned char*)buf+len);
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