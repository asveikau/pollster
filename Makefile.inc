ifndef LIBPOLLSTER_INC
LIBPOLLSTER_INC=y

LIBCOMMON_ROOT?=$(LIBPOLLSTER_ROOT)../common/
include $(LIBCOMMON_ROOT)Makefile.inc

LIBPOLLSTER_CXXFLAGS += -fno-rtti
LIBPOLLSTER_CXXFLAGS += -I$(LIBCOMMON_ROOT)include
LIBPOLLSTER_CXXFLAGS += -I$(LIBPOLLSTER_ROOT)include

LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends.cc \
   $(LIBPOLLSTER_ROOT)src/commonqueue.cc \
   $(LIBPOLLSTER_ROOT)src/threads.cc \
   $(LIBPOLLSTER_ROOT)src/timer.cc \
   $(LIBPOLLSTER_ROOT)src/messagequeue.cc

ifeq ($(PLATFORM), windows)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/win.cc
else
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/unix.cc
endif

ifneq (, $(filter $(PLATFORM),freebsd openbsd netbsd darwin))
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/kqueue.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_KQUEUE
endif

ifeq ($(PLATFORM),linux)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/epoll.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_EPOLL

GLIBC_MAJOR_TEST:=$(shell $(CC) -E -dM -include stdio.h - < /dev/null|grep ' __GLIBC__ ' | cut -d ' ' -f 3)
ifneq ($(GLIBC_MAJOR_TEST),)
GLIBC_MAJOR:=$(GLIBC_MAJOR_TEST)
GLIBC_MINOR:=$(shell $(CC) -E -dM -include stdio.h - < /dev/null|grep ' __GLIBC_MINOR__ ' | cut -d ' ' -f 3)
endif
endif

ifneq ($(PLATFORM), windows)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/poll.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_POLL
endif

ifndef HAS_GAI_IMPL
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/getaddrinfo.cc
endif

LIBPOLLSTER_OBJS := $(shell $(SRC2OBJ) $(LIBPOLLSTER_SRC))

LIBPOLLSTER:=$(LIBPOLLSTER_ROOT)$(LIBPREFIX)pollster$(LIBSUFFIX)

$(LIBPOLLSTER): ${LIBPOLLSTER_OBJS}
	$(LIBWRAPPER) $(LIBPOLLSTER_OBJS)

-include $(LIBPOLLSTER_ROOT)depend.mk

endif