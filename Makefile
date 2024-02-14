
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
all: $(APPNAME) $(APPNAME2)

clean:
	$(RM) $(APPNAME) $(APPNAME2)

$(APPNAME): $(APPNAME).c common.c
	$(CC) -s $(CFLAGS) -o $@ $^ $(LIBS)

$(APPNAME2): $(APPNAME2).c common.c
	$(CC) -s $(CFLAGS) -DINTERACTIVE -o $@ $^ $(LIBS)
