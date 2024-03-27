
LIBUSB = 1
CFLAGS = -O2 -Wall -Wextra -std=c99 -pedantic -Wno-unused
CFLAGS += -DUSE_LIBUSB=$(LIBUSB)
LIBS = -lm
APPNAME = spd_dump
APPNAME2 = spd_dump_interactive

ifeq ($(LIBUSB), 1)
LIBS += -lusb-1.0
endif

.PHONY: all clean
all: GITVER.h $(APPNAME) $(APPNAME2)

clean:
	$(RM) GITVER.h $(APPNAME) $(APPNAME2)

GITVER.h:
	echo "#define GIT_VER \"$(shell git rev-parse --abbrev-ref HEAD)\"" > GITVER.h
	echo "#define GIT_SHA1 \"$(shell git rev-parse HEAD)\"" >> GITVER.h

$(APPNAME): $(APPNAME).c common.c
	$(CC) -s $(CFLAGS) -o $@ $^ $(LIBS)

$(APPNAME2): $(APPNAME2).c common.c
	$(CC) -s $(CFLAGS) -DINTERACTIVE -o $@ $^ $(LIBS)
