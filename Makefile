
LIBUSB = 1
LIBXML2_CFLAGS := $(shell pkg-config --static --cflags libxml-2.0)
LIBXML2_LDFLAGS := $(shell pkg-config --static --libs libxml-2.0)
CFLAGS = -O2 -Wall -Wextra -std=c99 -pedantic -Wno-unused -static
CFLAGS += -DUSE_LIBUSB=$(LIBUSB) $(LIBXML2_CFLAGS)
LIBS = $(LIBXML2_LDFLAGS) -lm -lpthread

APPNAME = spd_dump

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
