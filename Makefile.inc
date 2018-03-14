
LIBCOMMON_ROOT=../common/
include $(LIBCOMMON_ROOT)Makefile.inc

LIBWAIT_CXXFLAGS += -fno-rtti
LIBWAIT_CXXFLAGS += -I$(LIBCOMMON_ROOT)include
LIBWAIT_CXXFLAGS += -I$(LIBWAIT_ROOT)include

LIBWAIT_SRC += \
   $(LIBWAIT_ROOT)src/unix.cc

ifneq (, $(filter $(PLATFORM),freebsd openbsd darwin))
LIBWAIT_SRC += \
   $(LIBWAIT_ROOT)src/kqueue.cc
LIBWAIT_CXXFLAGS += -DUSE_KQUEUE
endif

LIBWAIT_OBJS := $(shell $(SRC2OBJ) $(LIBWAIT_SRC))

LIBWAIT=$(LIBWAIT_ROOT)$(LIBPREFIX)wait$(LIBSUFFIX)

$(LIBWAIT): ${LIBWAIT_OBJS}
	$(LIBWRAPPER) $(LIBWAIT_OBJS)

-include $(LIBWAIT_ROOT)depend.mk

