CC = gcc
CFLAGS = `pkg-config fuse3 --cflags` -Wall -g
LDFLAGS = `pkg-config fuse3 --libs` -lssl -lcrypto

all: memfs

memfs: memfs.c
	$(CC) $(CFLAGS) memfs.c -o memfs $(LDFLAGS)

clean:
	rm -f memfs

