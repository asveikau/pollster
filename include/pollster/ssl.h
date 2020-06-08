/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_ssl_h_
#define pollster_ssl_h_

#include <functional>
#include <memory>

#include <pollster/filter.h>
#include <common/c++/stream.h>

namespace pollster
{

struct Certificate : public common::RefCountable
{
   virtual void *
   GetNativeObject() = 0;
};

struct SslArgs
{
   bool ServerMode;
   const char *HostName;
   common::Pointer<Certificate> Certificate;

   SslArgs() :
      ServerMode(false),
      HostName(nullptr)
   {}

   struct CallbackStruct
   {
      std::function<void(const char *, error *err)> OnCipherKnown;
   };
   CallbackStruct Callbacks;
};

void
InitSslLibrary(error *err);

void
CreateCertificate(
   common::Stream *stream,
   Certificate **output,
   error *err
);

void
CreateSslFilter(
   SslArgs &args,
   std::shared_ptr<Filter> &res,
   error *err
);

} // end namespace

#endif
