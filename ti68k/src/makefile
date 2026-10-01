CC      = cc
CFLAGS  = -w -Wall -Wextra
LDFLAGS = -Wl,--allow-multiple-definition -lssl -lcrypto 
DBGFLAGS = -O1 -g -fno-omit-frame-pointer -fno-lto
RM      = rm -f
UNAME  := $(shell uname)

ifeq ($(UNAME),FreeBSD)
	CFLAGS += -D BSD
else ifeq ($(UNAME),Linux)
	CFLAGS += -D LINUX
	LDFLAGS += -l:libbsd.so
endif

default: tiaes

tiaes:
	$(CC) $(CFLAGS) -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS)

debug:
	$(CC) $(CFLAGS) $(DBGFLAGS) -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS) -fno-lto

strip:
	$(CC) $(CFLAGS) -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS) -s

clean:
	$(RM) tiaes
