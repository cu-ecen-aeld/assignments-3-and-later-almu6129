CC ?= gcc

LDFLAGS ?=

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
        CC = aarch64-none-linux-gnu-gcc
endif

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) aesdsocket.o -o aesdsocket

aesdsocket.o: aesdsocket.c
	$(CC) -c aesdsocket.c -D_GNU_SOURCE

clean:
	rm -f aesdsocket.o aesdsocket
