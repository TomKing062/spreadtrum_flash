
LIBUSB = 1
CFLAGS = -O2 -Wall -Wextra -std=c99 -pedantic -Wno-unused -I/usr/include/libxml2 -L/usr/lib
CFLAGS += -DUSE_LIBUSB=$(LIBUSB)
LIBS = -lm -lpthread -lxml2 -lz -liconv
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
	$(CC) -s $(CFLAGS) -o $@ $^ $(LIBS)
