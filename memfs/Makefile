CC = gcc
CFLAGS = `pkg-config fuse3 --cflags` -Wall -g
LDFLAGS = `pkg-config fuse3 --libs` -lssl -lcrypto

SOURCES = main.c node.c encryption.c operations.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = memfs.h node.h encryption.h operations.h

all: memfs

memfs: $(OBJECTS)
	$(CC) $(CFLAGS) -o memfs $(OBJECTS) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f memfs $(OBJECTS)

