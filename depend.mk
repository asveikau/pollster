# This file was generated by "make depend".
#

$(LIBPOLLSTER_ROOT)src/async/connect.o: $(LIBPOLLSTER_ROOT)src/async/connect.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/logger.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/error-gai.o: $(LIBPOLLSTER_ROOT)src/async/error-gai.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/getaddrinfo-a.o: $(LIBPOLLSTER_ROOT)src/async/getaddrinfo-a.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/getaddrinfo.o: $(LIBPOLLSTER_ROOT)src/async/getaddrinfo.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/posix-aio.o: $(LIBPOLLSTER_ROOT)src/async/posix-aio.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/ring.h $(LIBCOMMON_ROOT)include/common/c++/scheduler.h $(LIBCOMMON_ROOT)include/common/c++/worker.h $(LIBCOMMON_ROOT)include/common/cas.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/path.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/sem.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/sleep.o: $(LIBPOLLSTER_ROOT)src/async/sleep.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/streamserver.o: $(LIBPOLLSTER_ROOT)src/async/streamserver.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/win.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/streamsocket.o: $(LIBPOLLSTER_ROOT)src/async/streamsocket.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/rwlock-self.h $(LIBCOMMON_ROOT)include/common/rwlock.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/waiter.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/win.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/async/winasync.o: $(LIBPOLLSTER_ROOT)src/async/winasync.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/win.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/backends.o: $(LIBPOLLSTER_ROOT)src/backends/backends.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/devpoll.o: $(LIBPOLLSTER_ROOT)src/backends/devpoll.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/epoll.o: $(LIBPOLLSTER_ROOT)src/backends/epoll.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/eventport.o: $(LIBPOLLSTER_ROOT)src/backends/eventport.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/kqueue.o: $(LIBPOLLSTER_ROOT)src/backends/kqueue.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/poll.o: $(LIBPOLLSTER_ROOT)src/backends/poll.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/threads.o: $(LIBPOLLSTER_ROOT)src/backends/threads.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/timer.o: $(LIBPOLLSTER_ROOT)src/backends/timer.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/time.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/unix.o: $(LIBPOLLSTER_ROOT)src/backends/unix.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/rwlock-self.h $(LIBCOMMON_ROOT)include/common/rwlock.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/waiter.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/backends/win.o: $(LIBPOLLSTER_ROOT)src/backends/win.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/win.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/test/test.o: $(LIBPOLLSTER_ROOT)src/test/test.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/logger.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/test/tunnel.o: $(LIBPOLLSTER_ROOT)src/test/tunnel.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/logger.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/tls/openssl.o: $(LIBPOLLSTER_ROOT)src/tls/openssl.cc $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/rwlock-self.h $(LIBCOMMON_ROOT)include/common/rwlock.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/waiter.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/tls/schannel.o: $(LIBPOLLSTER_ROOT)src/tls/schannel.cc $(LIBCOMMON_ROOT)include/common/c++/linereader.h $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/rwlock-self.h $(LIBCOMMON_ROOT)include/common/rwlock.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/waiter.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/tls/securetransport.o: $(LIBPOLLSTER_ROOT)src/tls/securetransport.cc $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/rwlock-self.h $(LIBCOMMON_ROOT)include/common/rwlock.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/waiter.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/afunix-legacy-win.o: $(LIBPOLLSTER_ROOT)src/util/afunix-legacy-win.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/c++/stream.h $(LIBCOMMON_ROOT)include/common/crypto/rng.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/path.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/win.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/afunix.o: $(LIBPOLLSTER_ROOT)src/util/afunix.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/path.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/commonqueue.o: $(LIBPOLLSTER_ROOT)src/util/commonqueue.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/sem.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/messagequeue.o: $(LIBPOLLSTER_ROOT)src/util/messagequeue.cc $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/rwlock-self.h $(LIBCOMMON_ROOT)include/common/rwlock.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/waiter.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/sa-string.o: $(LIBPOLLSTER_ROOT)src/util/sa-string.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/sigev.o: $(LIBPOLLSTER_ROOT)src/util/sigev.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/socklen.o: $(LIBPOLLSTER_ROOT)src/util/socklen.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/util/winsock.o: $(LIBPOLLSTER_ROOT)src/util/winsock.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
