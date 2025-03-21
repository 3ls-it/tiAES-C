CC      = cc
CFLAGS  = -w -Wall -Wextra
LDFLAGS = -Wl,--allow-multiple-definition -lssl -lcrypto 
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
	$(CC) $(CFLAGS) -g -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS)

strip:
	$(CC) $(CFLAGS) -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS) -s

clean:
	$(RM) tiaes
