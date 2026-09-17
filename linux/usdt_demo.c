// usdt_demo.c — a tiny program with a USDT marker, for trying honey's `usdt`
// probes. Build inside the honey Linux environment (needs sys/sdt.h from
// systemtap-sdt-dev):  make -C linux usdt_demo
//
// The marker is `honey:tick`. It also declares a semaphore, so the program
// can tell when something is attached: it prints "enabled" only then. That
// is exactly what real USDT users (Python, PostgreSQL, node) do to avoid
// preparing probe arguments nobody is watching.
#include <stdio.h>
#include <unistd.h>
// Ask sdt.h to reference a `<provider>_<name>_semaphore` for each marker, so
// the note carries its address and the kernel bumps it while attached.
#define _SDT_HAS_SEMAPHORES 1
#include <sys/sdt.h>

unsigned short honey_tick_semaphore __attribute__((section(".probes")));

int main(void) {
    for (int i = 0; ; i++) {
        if (honey_tick_semaphore) printf("tick %d (probe enabled)\n", i);
        else printf("tick %d\n", i);
        fflush(stdout);
        DTRACE_PROBE1(honey, tick, i);
        usleep(200000);
    }
}
