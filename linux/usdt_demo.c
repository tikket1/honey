// usdt_demo.c — a tiny program with a USDT marker, for trying honey's `usdt`
// probes. Build inside the honey Linux environment (needs sys/sdt.h from
// systemtap-sdt-dev):  make -C linux usdt_demo
//
// The marker is `honey:tick` with two arguments: the tick counter (an int)
// and a message (a C string). The note in the binary records where each
// argument lives — a register or a stack slot — and honey's loader turns
// that into a spec the probe reads at runtime, so `arg(0)` and `arg(1)`
// just work.
//
// It also declares a semaphore, so the program can tell when something is
// attached: it prints "probe enabled" only then. That is exactly what real
// USDT users (Python, PostgreSQL, node) do to avoid preparing probe data
// nobody is watching.
#include <stdio.h>
#include <unistd.h>
// Ask sdt.h to reference a `<provider>_<name>_semaphore` for each marker, so
// the note carries its address and the kernel bumps it while attached.
#define _SDT_HAS_SEMAPHORES 1
#include <sys/sdt.h>

unsigned short honey_tick_semaphore __attribute__((section(".probes")));

int main(void) {
    const char *messages[] = { "hello", "world", "from", "usdt" };
    for (int i = 0; ; i++) {
        const char *msg = messages[i % 4];
        if (honey_tick_semaphore) printf("tick %d %s (probe enabled)\n", i, msg);
        else printf("tick %d %s\n", i, msg);
        fflush(stdout);
        DTRACE_PROBE2(honey, tick, i, msg);
        usleep(200000);
    }
}
