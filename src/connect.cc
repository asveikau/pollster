#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <pollster/pollster.h>

#include <common/logger.h>

void
pollster::ConnectAsync(
   pollster::waiter *waiterp,
   const char *host,
   const char *service,
   std::function<void(ConnectAsyncStatus, const char *, error *)> onProgress,
   std::function<void(const std::shared_ptr<common::SocketHandle> &, error *)> onResult,
   std::function<void(error *)> onError
)
{
   common::Pointer<waiter> waiter;
   addrinfo hint = {0};
   error err;

   if (waiterp)
      waiter = waiterp;
   else
   {
      pollster::get_common_queue(waiter.GetAddressOf(), &err);
      ERROR_CHECK(&err);
   }

   hint.ai_socktype = SOCK_STREAM;

   if (onProgress)
   {
      onProgress(HostLookup, host, &err);
      ERROR_CHECK(&err);

      try
      {
         auto innerOnResult = onResult;
         onResult = [onProgress, innerOnResult]
         (const std::shared_ptr<common::SocketHandle> &r, error *err) -> void
         {
            onProgress(Connected, nullptr, err);
            ERROR_CHECK(err);
            innerOnResult(r, err);
            ERROR_CHECK(err);
         exit:;
         };
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(&err, nomem);
      }
   }

   try
   {
      GetAddrInfoAsync(
         host,
         service,
         &hint,
         [waiter, onProgress, onResult, onError] (const std::shared_ptr<struct addrinfo> &info, error *err) -> void
         {
            std::shared_ptr<common::SocketHandle> fd;
            common::Pointer<pollster::socket_event> sev;

            if (onProgress)
            {
               onProgress(Connect, nullptr, err);
               ERROR_CHECK(err);
            }

            try
            {
               fd = std::make_shared<common::SocketHandle>();
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }

            *fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
            if (!fd->Valid())
               ERROR_SET(err, socket);

            set_nonblock(fd->Get(), true, err);
            ERROR_CHECK(err);

            if (connect(fd->Get(), info->ai_addr, info->ai_addrlen))
            {
               auto r = SOCKET_LASTERROR;

               if (r == SOCK_ERROR(EINPROGRESS) || r == SOCK_ERROR(EWOULDBLOCK))
               {
                  try
                  {
                     waiter->add_socket(
                        fd,
                        true,
                        [fd, onError, onResult, info] (socket_event *sev, error *err) -> void
                        {
                           sev->on_error = onError;
                           sev->on_signal = [sev, fd, onResult, info] (error *err) -> void
                           {
                              int error = 0;
                              socklen_t socklen = sizeof(error);
                              common::Pointer<socket_event> sevStrong;

                              if (getsockopt(fd->Get(), SOL_SOCKET, SO_ERROR, &error, &socklen))
                                 ERROR_SET(err, socket);

                              if (error)
                              {
                                 error_set_socket(err, error);
                                 ERROR_LOG(err);
                                 goto exit;
                              }

                              sevStrong = sev;

                              sev->remove(err);
                              ERROR_CHECK(err);

                              onResult(fd, err);
                              ERROR_CHECK(err);
                           exit:;
                           };
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
                  goto exit;
               }

               error_set_socket(err, r);
               ERROR_LOG(err);
               goto exit;
            }

            sev->remove(err);
            sev = nullptr;
            ERROR_CHECK(err);

            onResult(fd, err);
            ERROR_CHECK(err);

         exit:
            if (ERROR_FAILED(err) && sev.Get())
            {
               error innerErr;
               sev->remove(&innerErr);
            }
         },
         onError
      );
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

exit:
   if (ERROR_FAILED(&err) && onError)
      onError(&err);
}

void
pollster::LogConnectAsyncStatus(pollster::ConnectAsyncStatus status, const char *arg)
{
   const char *fmt = nullptr;

   switch (status)
   {
   case HostLookup:
      fmt = arg ? "Looking up host %s" : "Looking up host";
      break;
   case Connect:
      fmt = arg ? "Connecting to %s" : "Connecting";
      break;
   case Connected:
      fmt = arg ? "Connection to %s established" : "Connection established";
      break;
   }

   if (fmt)
      log_printf(fmt, arg);
}
