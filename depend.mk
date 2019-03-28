# This file was generated by "make depend".
#

$(LIBPOLLSTER_ROOT)src/backends.o: $(LIBPOLLSTER_ROOT)src/backends.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/commonqueue.o: $(LIBPOLLSTER_ROOT)src/commonqueue.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/sem.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/connect.o: $(LIBPOLLSTER_ROOT)src/connect.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/logger.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/devpoll.o: $(LIBPOLLSTER_ROOT)src/devpoll.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/epoll.o: $(LIBPOLLSTER_ROOT)src/epoll.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/error-gai.o: $(LIBPOLLSTER_ROOT)src/error-gai.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/eventport.o: $(LIBPOLLSTER_ROOT)src/eventport.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/getaddrinfo-a.o: $(LIBPOLLSTER_ROOT)src/getaddrinfo-a.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/getaddrinfo.o: $(LIBPOLLSTER_ROOT)src/getaddrinfo.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/kqueue.o: $(LIBPOLLSTER_ROOT)src/kqueue.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/messagequeue.o: $(LIBPOLLSTER_ROOT)src/messagequeue.cc $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/poll.o: $(LIBPOLLSTER_ROOT)src/poll.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/streamserver.o: $(LIBPOLLSTER_ROOT)src/streamserver.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/streamsocket.o: $(LIBPOLLSTER_ROOT)src/streamsocket.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/lock.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/test.o: $(LIBPOLLSTER_ROOT)src/test.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/logger.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/threads.o: $(LIBPOLLSTER_ROOT)src/threads.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/timer.o: $(LIBPOLLSTER_ROOT)src/timer.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBCOMMON_ROOT)include/common/time.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/unix.o: $(LIBPOLLSTER_ROOT)src/unix.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/win.o: $(LIBPOLLSTER_ROOT)src/win.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/new.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/lazy.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/thread.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/messagequeue.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/threads.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/win.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
