#include <pollster/socket.h>
#include <pollster/pollster.h>

void
pollster::ConnectAsync(
   const char *host,
   const char *service,
   std::function<void(ConnectAsyncStatus, const char *, error *)> onProgress,
   std::function<void(const std::shared_ptr<common::SocketHandle>, error *)> onResult,
   std::function<void(error *)> onError
)
{
   addrinfo hint = {0};
   error err;

   hint.ai_socktype = SOCK_STREAM;

   if (onProgress)
   {
      onProgress(HostLookup, host, &err);
      ERROR_CHECK(&err);
   }

   try
   {
      GetAddrInfoAsync(
         host,
         service,
         &hint,
         [onProgress, onResult, onError] (struct addrinfo *info, error *err) -> void
         {
            std::shared_ptr<common::SocketHandle> fd;

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

            if (onProgress)
            {
               onProgress(HostLookup, nullptr, err);
               ERROR_CHECK(err);
            }

            if (connect(fd->Get(), info->ai_addr, info->ai_addrlen))
               ERROR_SET(err, socket);

            set_nonblock(fd->Get(), true, err);
            ERROR_CHECK(err);

            onResult(fd, err);
            ERROR_CHECK(err);
         exit:;
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
