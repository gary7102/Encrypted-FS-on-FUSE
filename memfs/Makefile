CC = gcc
CFLAGS = `pkg-config fuse3 --cflags` -Wall -g
LDFLAGS = `pkg-config fuse3 --libs` -lssl -lcrypto

all: memfs

memfs: memfs.c generate_random_key.c generate_random_key.h
	$(CC) $(CFLAGS) memfs.c generate_random_key.c -o memfs $(LDFLAGS)

clean:
	rm -f memfs

