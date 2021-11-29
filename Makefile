.PHONY: all all-phony clean depend
all: all-phony

CFLAGS += -g -Wall
WINDOWS_SUBSYSTEM=console
include Makefile.inc
CXXFLAGS += $(CFLAGS)

all-phony: $(LIBPOLLSTER) $(LIBPOLLSTER_ROOT)test$(EXESUFFIX) $(LIBPOLLSTER_ROOT)tunnel$(EXESUFFIX)

$(LIBPOLLSTER_ROOT)test$(EXESUFFIX): $(LIBPOLLSTER_ROOT)src/test/test.o $(LIBPOLLSTER) $(LIBCOMMON) $(XP_SUPPORT_OBJS)
	${CXX} -o $@ $< -L. -lpollster -L$(LIBCOMMON_ROOT) -lcommon $(CXXLIBS) $(LDFLAGS)

$(LIBPOLLSTER_ROOT)tunnel$(EXESUFFIX): $(LIBPOLLSTER_ROOT)src/test/tunnel.o $(LIBPOLLSTER) $(LIBCOMMON) $(XP_SUPPORT_OBJS)
	${CXX} -o $@ $< -L. -lpollster -L$(LIBCOMMON_ROOT) -lcommon $(CXXLIBS) $(LDFLAGS)

clean:
	rm -f $(LIBCOMMON) $(LIBCOMMON_OBJS)
	rm -f $(LIBPOLLSTER) $(LIBPOLLSTER_OBJS)
	rm -f $(LIBPOLLSTER_ROOT)test$(EXESUFFIX) $(LIBPOLLSTER_ROOT)src/test/test.o $(XP_SUPPORT_OBJS)
	rm -f $(LIBPOLLSTER_ROOT)tunnel$(EXESUFFIX) $(LIBPOLLSTER_ROOT)src/test/tunnel.o $(XP_SUPPORT_OBJS)

export
depend:
	env PROJECT=LIBPOLLSTER $(DEPEND) \
           src/async/*.cc \
           src/backends/*.cc \
           src/test/*.cc \
           src/tls/*.cc \
           src/util/*.cc \
        > depend.mk

