/*
 Copyright (C) 2021 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/sockapi.h>
#include <pollster/pollster.h>

#include <common/logger.h>
#include <common/misc.h>

#include <stdio.h>
#include <string.h>

using namespace common;
using namespace pollster;

#define VALID_PORT(PORT) \
   ((PORT) > 0 && (PORT) <= 0xffff)

namespace
{

struct ClientForwarder
{
   std::function<void(const std::shared_ptr<StreamSocket> &, error *)> PrepareRemoteClient;

   void
   OnClientConnected(const std::shared_ptr<StreamSocket> &fd, error *err)
   {
      std::shared_ptr<StreamSocket> remoteClient;
      try
      {
         remoteClient = std::make_shared<StreamSocket>();
      }
      catch (const std::bad_alloc &)
      {
         ERROR_SET(err, nomem);
      }

      {
         auto regCallbacks = [&] (
            const std::shared_ptr<StreamSocket> &one,
            const std::shared_ptr<StreamSocket> &other
         ) -> void
         {
            one->on_error = one->on_closed = [other] (error *err) -> void
            {
               other->Close();

               other->on_error = other->on_closed = [] (error *err) -> void {};
               other->on_recv = [] (const void *buf, size_t n, error *err) -> void {};
            };
            one->on_recv = [other] (const void *buf, size_t n, error *err) -> void
            {
               other->Write(buf, n);
            };
         };

         regCallbacks(fd, remoteClient);
         regCallbacks(remoteClient, fd);
      }

      PrepareRemoteClient(remoteClient, err);
      ERROR_CHECK(err);
   exit:;
   }
};

} // end namespace

int
main(int argc, char **argv)
{
   error err;
   Pointer<waiter> waiter;
   StreamServer server, serverSsl;
   static Pointer<Certificate> pem;
   bool sawSsl = false;
   bool sawServer = false;
   bool sawClient = false;
   std::shared_ptr<ClientForwarder> forwarder;
   std::function<void(const std::shared_ptr<StreamSocket> &, error *)> onClient;
   const char *hostOverride = nullptr;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   create(waiter.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   set_common_queue(waiter.Get());

   try
   {
      forwarder = std::make_shared<ClientForwarder>();
   }
   catch (const std::bad_alloc &)
   {
      ERROR_SET(&err, nomem);
   }

   onClient = [forwarder] (const std::shared_ptr<StreamSocket> &fd, error *err) -> void
   {
      forwarder->OnClientConnected(fd, err);
   };

   for (int i=1; i<argc; ++i)
   {
      auto arg = argv[i];

      if (!strcmp(arg, "-server"))
      {
         const char *type = nullptr;
         int port = -1;

         if (i + 2 >= argc)
         {
         usage_server:
            ERROR_SET(&err, unknown, "Usage: -server <unix path>|<tcp port>|<tls port>");
         }

         type = argv[i+1];
         arg = argv[i+2];
         i += 2;

         if (!strcmp(type, "ssl") || !strcmp(type, "tls"))
         {
            sawSsl = true;

            if (!check_atoi(arg, &port) || !VALID_PORT(port))
               goto usage_server;

            if (!serverSsl.on_client)
            {
               serverSsl.on_client = [onClient] (const std::shared_ptr<StreamSocket> &fd, error *err) -> void
               {
                  SslArgs ssl;

                  ssl.ServerMode = true;
                  ssl.Certificate = pem;

                  CreateSslFilter(ssl, fd->filter, err);
                  ERROR_CHECK(err);
                  fd->CheckFilter(err);
                  ERROR_CHECK(err);

                  onClient(fd, err);
               exit:;
               };
            }

            serverSsl.AddPort(port, &err);
            ERROR_CHECK(&err);
         }
         else if (!strcmp(type, "tcp"))
         {
            if (!check_atoi(arg, &port) || !VALID_PORT(port))
               goto usage_server;

            if (!server.on_client)
               server.on_client = onClient;

            server.AddPort(port, &err);
            ERROR_CHECK(&err);
         }
         else if (!strcmp(type, "unix"))
         {
            if (!server.on_client)
               server.on_client = onClient;

            server.AddUnixDomain(arg, &err);
            ERROR_CHECK(&err);
         }
         else
            goto usage_server;

         sawServer = true;
      }
      else if (!strcmp(arg, "-client"))
      {
         if (i + 2 >= argc)
         {
         usage_client:
            ERROR_SET(&err, unknown, "Usage: -client <unix path>|<tcp host:port>|<tls host:port>");
         }

         const char *host = nullptr;
         int port = -1;
         auto type = argv[i+1];
         arg = argv[i+2];
         i += 2;

         auto parseHost = [&] () -> bool
         {
            char *port_s = arg;

            if (*arg == '[')
            {
               port_s = strchr(++arg, ']');
               if (!port_s)
                  return false;
               *port_s++ = '0';
            }

            port_s = strchr(port_s, ':');
            if (!port_s)
               return false;
            *port_s++ = 0;

            if (!check_atoi(port_s, &port) || !VALID_PORT(port))
               return false;

            host = arg;

            return true;
         };

         if (!strcmp(type, "ssl") || !strcmp(type, "tls"))
         {
            if (!parseHost())
               goto usage_client;

            forwarder->PrepareRemoteClient = [&hostOverride, host, port] (const std::shared_ptr<StreamSocket> &fd, error *err) -> void
            {
               SslArgs args;
               char service[64];

               args.HostName = hostOverride ? hostOverride : host;
               CreateSslFilter(args, fd->filter, err);
               ERROR_CHECK(err);

               snprintf(service, sizeof(service), "%d", port);
               fd->Connect(host, service);

            exit:;
            };
         }
         else if (!strcmp(type, "tcp"))
         {
            if (!parseHost())
               goto usage_client;

            forwarder->PrepareRemoteClient = [host, port] (const std::shared_ptr<StreamSocket> &fd, error *err) -> void
            {
               char service[64];

               snprintf(service, sizeof(service), "%d", port);
               fd->Connect(host, service);
            };
         }
         else if (!strcmp(type, "unix"))
         {
            forwarder->PrepareRemoteClient = [arg] (const std::shared_ptr<StreamSocket> &fd, error *err) -> void
            {
               fd->ConnectUnixDomain(arg);
            };
         }
         else
            goto usage_client;

         if (sawClient)
            ERROR_SET(&err, unknown, "-client specified twice");
         sawClient = true;
      }
      else if (!strcmp(arg, "-pemfile"))
      {
         if (i + 1 >= argc)
            ERROR_SET(&err, unknown, "Usage: -pemfile <filename>");
         ++i;
         auto pemFilename = argv[i];
         Pointer<Stream> pemStream;

         if (pem.Get())
            ERROR_SET(&err, unknown, "-pemfile specified twice");

         CreateStream(pemFilename, "r", pemStream.GetAddressOf(), &err);
         ERROR_CHECK(&err);
         CreateCertificate(pemStream.Get(), pem.GetAddressOf(), &err);
         ERROR_CHECK(&err);
      }
      else if (!strcmp(arg, "-host"))
      {
         if (i + 1 >= argc)
            ERROR_SET(&err, unknown, "Usage: -host <host name override>");
         hostOverride = argv[++i];
      }
      else
      {
         ERROR_SET(&err, unknown, "Valid options: -client, -server, -pemfile");
      }
   }

   if (!sawServer && !sawClient)
      ERROR_SET(&err, unknown, "Need -client and -server options");
   if (!sawServer)
      ERROR_SET(&err, unknown, "Need -server option");
   if (!sawClient)
      ERROR_SET(&err, unknown, "Need -client option");

   if (sawSsl && !pem.Get())
      ERROR_SET(&err, unknown, "tls server set, but no -pemfile specified");

   for (;;)
   {
      waiter->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
