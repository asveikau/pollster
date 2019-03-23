.PHONY: all all-phony clean depend
all: all-phony

CFLAGS += -O2 -Wall
include Makefile.inc
CXXFLAGS += $(CFLAGS)

all-phony: $(LIBPOLLSTER) $(LIBPOLLSTER_ROOT)test$(EXESUFFIX)

$(LIBPOLLSTER_ROOT)test$(EXESUFFIX): $(LIBPOLLSTER_ROOT)src/test.o $(LIBPOLLSTER) $(LIBCOMMON)
	${CXX} ${CXXFLAGS} ${LIBPOLLSTER_CXXFLAGS} -o $@ $< -L. -lpollster -L$(LIBCOMMON_ROOT) -lcommon $(CXXLIBS) $(LDFLAGS)

clean:
	rm -f $(LIBCOMMON) $(LIBCOMMON_OBJS)
	rm -f $(LIBPOLLSTER) $(LIBPOLLSTER_OBJS)
	rm -f $(LIBPOLLSTER_ROOT)test$(EXESUFFIX) $(LIBPOLLSTER_ROOT)src/test.o

export
depend:
	env PROJECT=LIBPOLLSTER $(DEPEND) src/*.cc > depend.mk

