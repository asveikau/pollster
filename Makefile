all: all-phony

CFLAGS += -O2 -Wall
include Makefile.inc
CXXFLAGS += $(CFLAGS)

all-phony: $(LIBWAIT)

clean:
	rm -f $(LIBCOMMON) $(LIBCOMMON_OBJS)
	rm -f $(LIBWAIT) $(LIBWAIT_OBJS)

export
depend:
	env PROJECT=LIBWAIT $(DEPEND) src/*.cc > depend.mk

