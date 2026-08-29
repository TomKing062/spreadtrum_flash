
MUSL_BUILD := 0
CFLAGS = -O2 -Wall -Wextra -std=c99 -pedantic -Wno-unused

ifeq ($(MUSL_BUILD),1)
    CFLAGS += -static
    LIBUSB_CFLAGS := $(shell PKG_CONFIG_PATH='$(USER_PKG_CONFIG_PATH)' pkg-config --static --cflags libusb-1.0)
    LIBUSB_LDFLAGS   := $(shell PKG_CONFIG_PATH='$(USER_PKG_CONFIG_PATH)' pkg-config --static --libs libusb-1.0)
    LIBXML2_CFLAGS := $(shell PKG_CONFIG_PATH='$(USER_PKG_CONFIG_PATH)' pkg-config --static --cflags libxml-2.0)
    LIBXML2_LDFLAGS   := $(shell PKG_CONFIG_PATH='$(USER_PKG_CONFIG_PATH)' pkg-config --static --libs libxml-2.0)
else
    LIBUSB_CFLAGS := $(shell pkg-config --cflags libusb-1.0)
    LIBUSB_LDFLAGS   := $(shell pkg-config --libs libusb-1.0)
    LIBXML2_CFLAGS := $(shell pkg-config --cflags libxml-2.0)
    LIBXML2_LDFLAGS   := $(shell pkg-config --libs libxml-2.0)
endif

CFLAGS += -DUSE_LIBUSB=1 $(LIBUSB_CFLAGS) $(LIBXML2_CFLAGS)
LIBS = $(LIBUSB_LDFLAGS) $(LIBXML2_LDFLAGS) -lm -lpthread

APPNAME = spd_dump

MYDEBUG := 0
ifeq ($(MYDEBUG), 1)
CFLAGS += -D_MYDEBUG
endif

STRIP := -s

.PHONY: all clean nostrip
all: clean GITVER.h $(APPNAME)

# Build without the -s (strip) linker flag, keeping debug symbols
nostrip: STRIP :=
nostrip: all

clean:
	$(RM) GITVER.h $(APPNAME)

GITVER.h:
	echo "#define GIT_VER \"$(shell git rev-list HEAD --count)\"" > GITVER.h
	echo "#define GIT_SHA1 \"$(shell git rev-parse HEAD)\"" >> GITVER.h

$(APPNAME): $(APPNAME).c common.c
	$(CC) $(STRIP) $(CFLAGS) $^ $(LIBS) -o $@
