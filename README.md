# libpollster

Yet another wrapper for poll, epoll, kqueue, etc.

A portable library for async socket I/O and some helpful event loop features.

## API

* The core "wait object" interface is in [`pollster.h`][1].  This provides:
    - Socket read or write readiness polling.
    - Auto-reset events, similar to Win32 `CreateEvent()` or Linux `eventfd(2)`. 
    - Timers.

* Atop this are some "simple" APIs for convenient asynchronous socket programming,
  in [`sockapi.h`][2].

* TLS/SSL support for both clients and servers can be added via [`ssl.h`][3].

## Requirements

Building happens via [the makefiles submodule][4].

    $ git submodule update --init
    $ make                             # or "gmake" on some platforms, like BSD

On Unix, the project builds with g++ 8.0 or higher (7 and earlier won't work!)
or clang++.

On Windows, GNU make, nasm and msysgit should be on PATH, and the project is
typically tested with VS2015 with Windows SDK 10586.

## Platform support

* Linux: epoll, async DNS via getaddrinfo_a()
* FreeBSD, OpenBSD, NetBSD, macOS: kqueue
* Solaris: port_create, /dev/poll
* Windows
    - Notably, this does not use I/O completion ports, but creates a separate
      thread for every 63 handles to call WaitForMultipleObjects().  So the
      Windows backend, while working, is not as good as it could be.

There is also a generic poll(2) based backend, if none of the more platform
specific methods are available. 

TLS support use:

* Windows: SChannel
* macOS: SecureTransport
* OpenSSL/LibreSSL etc., tested regularly on FreeBSD, OpenBSD, Linux.

[1]: https://github.com/asveikau/pollster/tree/master/include/pollster/pollster.h
[2]: https://github.com/asveikau/pollster/tree/master/include/pollster/sockapi.h
[3]: https://github.com/asveikau/pollster/tree/master/include/pollster/ssl.h
[4]: https://github.com/asveikau/makefiles

