# Build the honey loader. Run inside the honey Linux environment:
#   linux/honey-linux make -C linux
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS ?= -lbpf -lelf -lz

loader: loader.c
	$(CC) $(CFLAGS) -o $@ loader.c $(LDLIBS)

# A demo binary with a USDT marker (see usdt_demo.c).
usdt_demo: usdt_demo.c
	$(CC) -O1 -g -o $@ usdt_demo.c

clean:
	rm -f loader usdt_demo *.o
