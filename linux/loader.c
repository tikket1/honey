// honey loader: install a honey-compiled BPF program into the kernel.
//
//   loader <program.bin> <program.json>
//
// It reads the raw bytecode honeyc emitted and the JSON manifest describing
// it, creates the ring-buffer map, relocates the program's map reference to
// the real map fd, loads the program (the kernel verifier judges it here),
// attaches it to the named tracepoint, and prints each event the program
// pushes into the ring buffer, decoded per the manifest's field layout.
//
// This is deliberately low-level: no BPF skeleton, no CO-RE. honeyc produced
// the instructions; this is the userspace ABI that gets them running.

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// ----------------------------------------------------- tiny manifest reader
//
// The manifest is small and self-produced, so a scan-for-the-key reader is
// enough. Not a general JSON parser.

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(n + 1);
    if (fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
    buf[n] = 0;
    fclose(f);
    if (len) *len = n;
    return buf;
}

// Copy the string value of "key": "..." found after `from` into out.
// Returns a pointer just past the value, or NULL.
static const char *json_str(const char *from, const char *key, char *out, size_t cap) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(from, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), ':');
    if (!p) return NULL;
    p = strchr(p, '"');
    if (!p) return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) out[i++] = *p++;
    out[i] = 0;
    return *p == '"' ? p + 1 : NULL;
}

// Read the integer value of "key": N found after `from`.
static long json_int(const char *from, const char *key, long dflt) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(from, pat);
    if (!p) return dflt;
    p = strchr(p + strlen(pat), ':');
    if (!p) return dflt;
    return strtol(p + 1, NULL, 10);
}

// ------------------------------------------------------------- field layout

enum kind { K_UINT, K_STR, K_BOOL };

struct field {
    char name[32];
    uint32_t offset;
    uint32_t size;
    enum kind kind;
};

#define MAX_FIELDS 32

// ----------------------------------------------------------------- attaching

static int perf_event_open_tracepoint(int id) {
    struct perf_event_attr attr = {0};
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = id;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    // pid = -1, cpu = 0: any process, CPU 0. PERF_EVENT_IOC_SET_BPF binds the
    // program to the tracepoint itself, so this one event gives system-wide
    // coverage across every CPU.
    return syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
}

static int read_tracepoint_id(const char *cat, const char *name) {
    char path[256];
    snprintf(path, sizeof path,
             "/sys/kernel/tracing/events/%s/%s/id", cat, name);
    // tracefs files report size 0, so read directly rather than via slurp().
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s (is tracefs mounted?)\n", path);
        return -1;
    }
    int id = -1;
    if (fscanf(f, "%d", &id) != 1) id = -1;
    fclose(f);
    return id;
}

// ----------------------------------------------------------- event printing

struct ctx {
    struct field *fields;
    int n_fields;
    uint32_t size;
};

static int on_event(void *vctx, void *data, size_t len) {
    struct ctx *c = vctx;
    if (len < c->size) return 0;
    const uint8_t *rec = data;
    for (int i = 0; i < c->n_fields; i++) {
        struct field *f = &c->fields[i];
        const uint8_t *p = rec + f->offset;
        if (i) printf("  ");
        switch (f->kind) {
        case K_UINT: {
            uint64_t v = 0;
            memcpy(&v, p, f->size);
            printf("%s=%llu", f->name, (unsigned long long)v);
            break;
        }
        case K_BOOL:
            printf("%s=%s", f->name, *p ? "true" : "false");
            break;
        case K_STR:
            printf("%s=%.*s", f->name, (int)f->size, (const char *)p);
            break;
        }
    }
    printf("\n");
    fflush(stdout);
    return 0;
}

// ----------------------------------------------------- map fd relocation

// honeyc emits `ld64 r1, map_fd(0)` for the ring buffer: an 8-byte opcode
// 0x18 slot with src-reg nibble = 1 and imm = map index 0. Rewrite that
// imm to the real map fd before loading.
static void relocate_map_fd(uint8_t *insns, size_t bytes, int map_fd) {
    for (size_t i = 0; i + 16 <= bytes; ) {
        uint8_t opcode = insns[i];
        uint8_t src = insns[i + 1] >> 4;
        if (opcode == 0x18) {
            if (src == 1) { // PSEUDO_MAP_FD
                int32_t idx;
                memcpy(&idx, insns + i + 4, 4);
                if (idx == 0) {
                    memcpy(insns + i + 4, &map_fd, 4);
                }
            }
            i += 16; // wide instruction
        } else {
            i += 8;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <program.bin> <program.json>\n", argv[0]);
        return 2;
    }

    size_t code_len = 0;
    uint8_t *code = (uint8_t *)slurp(argv[1], &code_len);
    char *man = slurp(argv[2], NULL);
    if (!code || !man) return 1;
    if (code_len % 8 != 0) {
        fprintf(stderr, "bytecode length %zu is not a multiple of 8\n", code_len);
        return 1;
    }

    char license[16] = "GPL", cat[64], name[64], ev_name[64];
    json_str(man, "license", license, sizeof license);
    if (!json_str(man, "category", cat, sizeof cat) ||
        !json_str(man, "name", name, sizeof name)) {
        fprintf(stderr, "manifest missing tracepoint category/name\n");
        return 1;
    }
    long ringbuf_bytes = json_int(man, "ringbuf_bytes", 1 << 16);
    long ev_size = json_int(man, "size", 0);
    json_str(man, "name", ev_name, sizeof ev_name); // event name (first "name")

    // Parse the fields array.
    struct field fields[MAX_FIELDS];
    int nf = 0;
    const char *fp = strstr(man, "\"fields\"");
    while (fp && nf < MAX_FIELDS) {
        char kind[16];
        const char *after = json_str(fp, "name", fields[nf].name, sizeof fields[nf].name);
        if (!after) break;
        fields[nf].offset = json_int(fp, "offset", 0);
        fields[nf].size = json_int(fp, "size", 0);
        json_str(fp, "kind", kind, sizeof kind);
        fields[nf].kind = strcmp(kind, "str") == 0 ? K_STR
                        : strcmp(kind, "bool") == 0 ? K_BOOL : K_UINT;
        nf++;
        fp = strstr(after, "\"name\""); // next field object
    }

    // 1. Create the ring-buffer map.
    int map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "events", 0, 0, ringbuf_bytes, NULL);
    if (map_fd < 0) {
        fprintf(stderr, "bpf_map_create: %s\n", strerror(-map_fd));
        return 1;
    }

    // 2. Relocate the program's map reference to the real fd.
    relocate_map_fd(code, code_len, map_fd);

    // 3. Load the program. The verifier accepts or rejects here.
    char log[64 * 1024];
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
        .log_buf = log, .log_size = sizeof log, .log_level = 1);
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, name, license,
                                (const struct bpf_insn *)code, code_len / 8, &opts);
    if (prog_fd < 0) {
        fprintf(stderr, "verifier rejected the program (%s):\n%s\n", strerror(-prog_fd), log);
        return 1;
    }
    fprintf(stderr, "loaded: prog fd %d, %zu instructions\n", prog_fd, code_len / 8);

    // 4. Attach to the tracepoint.
    int id = read_tracepoint_id(cat, name);
    if (id < 0) return 1;
    int pfd = perf_event_open_tracepoint(id);
    if (pfd < 0) { perror("perf_event_open"); return 1; }
    if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) { perror("PERF_EVENT_IOC_SET_BPF"); return 1; }
    if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) { perror("PERF_EVENT_IOC_ENABLE"); return 1; }
    fprintf(stderr, "attached to %s/%s (id %d). event: %s (%ld bytes). waiting for events, Ctrl-C to stop...\n",
            cat, name, id, ev_name, ev_size);

    // 5. Poll the ring buffer and print events.
    struct ctx c = { .fields = fields, .n_fields = nf, .size = (uint32_t)ev_size };
    struct ring_buffer *rb = ring_buffer__new(map_fd, on_event, &c, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); return 1; }

    while (1) {
        int err = ring_buffer__poll(rb, 200 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "poll: %s\n", strerror(-err));
            break;
        }
    }
    return 0;
}
