CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g -std=gnu11
LFLAGS := -lpcap
DEFINES:= $(DEFINES)
CC     := gcc
BINARY := udpreplay
DEPS   := build/udpreplay.o

.PHONY: all clean dev test

all: build $(DEPS) link

dev: clean
	DEFINES="-DDEV" $(MAKE)

build:
	-mkdir build bin

%.o: $(patsubst build/%o,%c,$@)
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o $@ $(patsubst build/%o,%c,$@)

link: $(DEPS)
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -o bin/$(BINARY) $(DEPS) $(LFLAGS)

clean:
	rm -fv $(DEPS) bin/$(BINARY)
	-rmdir build bin

test:
	$(MAKE) -C test

install:
	cp bin/$(BINARY) /usr/bin/$(BINARY)

clang:
	$(MAKE) dev CC=clang
