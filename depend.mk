# This file was generated by "make depend".
#

$(LIBWAIT_ROOT)src/unix.o: $(LIBWAIT_ROOT)src/unix.cc $(LIBWAIT_ROOT)../common/include/common/c++/../refcnt.h $(LIBWAIT_ROOT)../common/include/common/c++/refcount.h $(LIBWAIT_ROOT)../common/include/common/error.h $(LIBWAIT_ROOT)include/wait/unix.h $(LIBWAIT_ROOT)include/wait/wait.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(LIBWAIT_CXXFLAGS) $(LIBWAIT_CFLAGS) -c -o $@ $<
