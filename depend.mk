# This file was generated by "make depend".
#

$(LIBPOLLSTER_ROOT)src/backends.o: $(LIBPOLLSTER_ROOT)src/backends.cc $(LIBPOLLSTER_ROOT)../common/include/common/c++/../refcnt.h $(LIBPOLLSTER_ROOT)../common/include/common/c++/refcount.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/kqueue.o: $(LIBPOLLSTER_ROOT)src/kqueue.cc $(LIBPOLLSTER_ROOT)../common/include/common/c++/../refcnt.h $(LIBPOLLSTER_ROOT)../common/include/common/c++/refcount.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)../common/include/common/misc.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/poll.o: $(LIBPOLLSTER_ROOT)src/poll.cc $(LIBPOLLSTER_ROOT)../common/include/common/c++/../refcnt.h $(LIBPOLLSTER_ROOT)../common/include/common/c++/refcount.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)../common/include/common/misc.h $(LIBPOLLSTER_ROOT)include/pollster/backends.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/test.o: $(LIBPOLLSTER_ROOT)src/test.cc $(LIBPOLLSTER_ROOT)../common/include/common/c++/../refcnt.h $(LIBPOLLSTER_ROOT)../common/include/common/c++/refcount.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)../common/include/common/logger.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/timer.o: $(LIBPOLLSTER_ROOT)src/timer.cc $(LIBPOLLSTER_ROOT)../common/include/common/c++/../refcnt.h $(LIBPOLLSTER_ROOT)../common/include/common/c++/refcount.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)../common/include/common/time.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
$(LIBPOLLSTER_ROOT)src/unix.o: $(LIBPOLLSTER_ROOT)src/unix.cc $(LIBPOLLSTER_ROOT)../common/include/common/c++/../refcnt.h $(LIBPOLLSTER_ROOT)../common/include/common/c++/refcount.h $(LIBPOLLSTER_ROOT)../common/include/common/error.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/timer.h $(LIBPOLLSTER_ROOT)include/pollster/unix.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBPOLLSTER_CXXFLAGS) $(LIBPOLLSTER_CFLAGS) -c -o $@ $<
