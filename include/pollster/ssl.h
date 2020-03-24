/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef pollster_ssl_h_
#define pollster_ssl_h_

#include <memory>

#include <pollster/filter.h>

namespace pollster
{

//
// TODO: needs more parameters
// [client cert, server keys, hostname]
//
struct SslArgs
{
   bool ServerMode;
};

void
CreateSslFilter(
   SslArgs &args,
   std::shared_ptr<Filter> &res,
   error *err
);

} // end namespace

#endif
