ifndef LIBPOLLSTER_INC
LIBPOLLSTER_INC=y

VERSION_CHECK:=perl $(LIBPOLLSTER_ROOT)scripts/version-check.pl

MAKEFILES_ROOT?=$(LIBPOLLSTER_ROOT)submodules/makefiles/
LIBCOMMON_ROOT?=$(LIBPOLLSTER_ROOT)submodules/common/
include $(LIBCOMMON_ROOT)Makefile.inc

LIBPOLLSTER_CXXFLAGS += -fno-rtti
LIBPOLLSTER_CXXFLAGS += -I$(LIBCOMMON_ROOT)include
LIBPOLLSTER_CXXFLAGS += -I$(LIBPOLLSTER_ROOT)include

LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/async/connect.cc \
   $(LIBPOLLSTER_ROOT)src/async/error-gai.cc \
   $(LIBPOLLSTER_ROOT)src/async/sleep.cc \
   $(LIBPOLLSTER_ROOT)src/async/streamserver.cc \
   $(LIBPOLLSTER_ROOT)src/async/streamsocket.cc \
   $(LIBPOLLSTER_ROOT)src/backends/backends.cc \
   $(LIBPOLLSTER_ROOT)src/backends/threads.cc \
   $(LIBPOLLSTER_ROOT)src/backends/timer.cc \
   $(LIBPOLLSTER_ROOT)src/util/afunix.cc \
   $(LIBPOLLSTER_ROOT)src/util/commonqueue.cc \
   $(LIBPOLLSTER_ROOT)src/util/messagequeue.cc \
   $(LIBPOLLSTER_ROOT)src/util/sa-string.cc \
   $(LIBPOLLSTER_ROOT)src/util/socklen.cc

ifeq ($(PLATFORM), windows)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/async/winasync.cc \
   $(LIBPOLLSTER_ROOT)src/backends/win.cc \
   $(LIBPOLLSTER_ROOT)src/util/afunix-legacy-win.cc \
   $(LIBPOLLSTER_ROOT)src/util/winsock.cc

LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/tls/schannel.cc
LIBPOLLSTER_CFLAGS += -DHAVE_SSL

ifdef FORCE_LEGACY_AFUNIX
LIBPOLLSTER_CXXFLAGS += -DTEST_LEGACY_UNIX_SOCKET
endif
else
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends/unix.cc
endif

ifneq (, $(filter $(PLATFORM),freebsd openbsd netbsd darwin))
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends/kqueue.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_KQUEUE
endif

ifeq ($(PLATFORM),linux)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends/epoll.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_EPOLL

GLIBC_MAJOR_TEST:=$(shell $(CC) -E -dM -include stdio.h - < /dev/null|grep '\#define __GLIBC__ ' | cut -d ' ' -f 3)
ifneq ($(GLIBC_MAJOR_TEST),)
GLIBC_MAJOR:=$(GLIBC_MAJOR_TEST)
GLIBC_MINOR:=$(shell $(CC) -E -dM -include stdio.h - < /dev/null|grep '\#define __GLIBC_MINOR__ ' | cut -d ' ' -f 3)
endif

ifdef GLIBC_MAJOR
ifeq ($(shell $(VERSION_CHECK) $(GLIBC_MAJOR).$(GLIBC_MINOR) 2.8), 1)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/async/getaddrinfo-a.cc
LDFLAGS += -lanl
HAS_GAI_IMPL:=y
endif
endif

endif

ifeq ($(PLATFORM), sunos)
SUNOS_VERSION:=$(shell uname -r)
ifeq ($(shell $(VERSION_CHECK) $(SUNOS_VERSION) 5.10), 1)
HAVE_EVENT_PORT:=y
endif # Solaris 10
ifeq ($(shell $(VERSION_CHECK) $(SUNOS_VERSION) 5.8), 1)
HAVE_DEV_POLL:=y
endif # Solaris 8
endif # Solaris

ifneq (, $(filter $(shell echo $(PLATFORM) | sed s/.*bsd$$/bsd/),linux bsd sunos))
USE_OPENSSL:=y
endif

ifdef HAVE_EVENT_PORT
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends/eventport.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_EVENT_PORT
endif

ifdef HAVE_DEV_POLL
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends/devpoll.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_DEV_POLL
endif

ifneq ($(PLATFORM), windows)
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/backends/poll.cc
LIBPOLLSTER_CXXFLAGS += -DUSE_POLL
endif

ifndef HAS_GAI_IMPL
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/async/getaddrinfo.cc
endif

ifeq ($(PLATFORM), darwin)
ifndef USE_OPENSSL
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/tls/securetransport.cc
LIBPOLLSTER_CFLAGS += -DHAVE_SSL
LDFLAGS += -framework Security
endif
endif

ifdef USE_OPENSSL
ifeq ($(PLATFORM), darwin)
# This is where MacPorts puts it.  Probably not widespread.
LIBPOLLSTER_CFLAGS += -I/opt/local/include
LDFLAGS += -L/opt/local/lib
# On yet another of my machines, pkgin puts it here.
LIBPOLLSTER_CFLAGS += -I/opt/pkg/include
LDFLAGS += -L/opt/pkg/lib
endif
LIBPOLLSTER_SRC += \
   $(LIBPOLLSTER_ROOT)src/tls/openssl.cc
LDFLAGS += -lssl -lcrypto
LIBPOLLSTER_CFLAGS += -DHAVE_SSL
endif

LIBPOLLSTER_OBJS := $(shell $(SRC2OBJ) $(LIBPOLLSTER_SRC))

LIBPOLLSTER:=$(LIBPOLLSTER_ROOT)$(LIBPREFIX)pollster$(LIBSUFFIX)

$(LIBPOLLSTER): ${LIBPOLLSTER_OBJS}
	$(LIBWRAPPER) $(LIBPOLLSTER_OBJS)

-include $(LIBPOLLSTER_ROOT)depend.mk

endif
