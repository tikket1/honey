# Build the honey loader. Run inside the honey Linux environment:
#   linux/honey-linux make -C linux
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS ?= -lbpf -lelf -lz

loader: loader.c
	$(CC) $(CFLAGS) -o $@ loader.c $(LDLIBS)

clean:
	rm -f loader *.o
