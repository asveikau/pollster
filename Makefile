all: all-phony

CFLAGS += -O2 -Wall
include Makefile.inc
CXXFLAGS += $(CFLAGS)

all-phony: $(LIBWAIT) test$(EXESUFFIX)

test$(EXESUFFIX): src/test.cc $(LIBWAIT)
	${CXX} ${CXXFLAGS} ${LIBWAIT_CXXFLAGS} -o $@ $< -L. -lwait -L$(LIBCOMMON_ROOT) -lcommon $(CXXLIBS)

clean:
	rm -f $(LIBCOMMON) $(LIBCOMMON_OBJS)
	rm -f $(LIBWAIT) $(LIBWAIT_OBJS)
	rm -f test$(EXESUFFIX)

export
depend:
	env PROJECT=LIBWAIT $(DEPEND) src/*.cc > depend.mk

