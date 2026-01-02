
LIBUSB = 1
CFLAGS = -O2 -Wall -Wextra -std=c99 -pedantic -Wno-unused
UNAME_S := $(shell uname -s)
ifeq ($(OS),Windows_NT)
    IS_WINDOWS := 1
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    IS_WINDOWS := 1
else ifneq (,$(findstring CYGWIN,$(UNAME_S)))
    IS_WINDOWS := 1
else
    IS_WINDOWS := 0
endif

ifeq ($(IS_WINDOWS),1)
    CFLAGS += -static
    LIBXML2_CFLAGS := $(shell pkg-config --static --cflags libxml-2.0)
    LIBXML2_LIBS   := $(shell pkg-config --static --libs libxml-2.0)
else
    LIBXML2_CFLAGS := $(shell pkg-config --cflags libxml-2.0)
    LIBXML2_LIBS   := $(shell pkg-config --libs libxml-2.0)
endif

CFLAGS += -DUSE_LIBUSB=$(LIBUSB) $(LIBXML2_CFLAGS)
LIBS = $(LIBXML2_LDFLAGS) -lm -lpthread

APPNAME = spd_dump

MYDEBUG := 0
ifeq ($(MYDEBUG), 1)
CFLAGS += -D_MYDEBUG
endif

ifeq ($(LIBUSB), 1)
LIBS += -lusb-1.0
endif

.PHONY: all clean
all: clean GITVER.h $(APPNAME)

clean:
	$(RM) GITVER.h $(APPNAME)

GITVER.h:
	echo "#define GIT_VER \"$(shell git rev-parse --abbrev-ref HEAD)\"" > GITVER.h
	echo "#define GIT_SHA1 \"$(shell git rev-parse HEAD)\"" >> GITVER.h

$(APPNAME): $(APPNAME).c common.c
	$(CC) -s $(CFLAGS) $^ $(LIBS) -o $@
