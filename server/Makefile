CC ?= $(CROSS_COMPILE)gcc

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) aesdsocket.o -o aesdsocket

aesdsocket.o: aesdsocket.c
	$(CC) -c aesdsocket.c -D_GNU_SOURCE

clean:
	rm -f aesdsocket.o aesdsocket
