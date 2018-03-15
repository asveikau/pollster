all: all-phony

CFLAGS += -O2 -Wall
include Makefile.inc
CXXFLAGS += $(CFLAGS)

all-phony: $(LIBPOLLSTER) test$(EXESUFFIX)

test$(EXESUFFIX): src/test.cc $(LIBPOLLSTER) $(LIBCOMMON)
	${CXX} ${CXXFLAGS} ${LIBPOLLSTER_CXXFLAGS} -o $@ $< -L. -lpollster -L$(LIBCOMMON_ROOT) -lcommon $(CXXLIBS)

clean:
	rm -f $(LIBCOMMON) $(LIBCOMMON_OBJS)
	rm -f $(LIBPOLLSTER) $(LIBPOLLSTER_OBJS)
	rm -f test$(EXESUFFIX)

export
depend:
	env PROJECT=LIBPOLLSTER $(DEPEND) src/*.cc > depend.mk

