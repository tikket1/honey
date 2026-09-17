// honey loader: install a honey-compiled program into the kernel.
//
//   loader <program.bin> <program.json>
//
// A honey program is one or more BPF programs (one per probe) that share a
// set of maps and one event ring buffer. The loader:
//
//   1. creates the maps (index 0 is the ring buffer, then the manifest's
//      "maps" in order),
//   2. for each program: slices its bytes out of the .bin, rewrites every
//      `ld64 rN, map_fd(i)` placeholder to the real fd, loads it (the kernel
//      verifier judges it here), and attaches it — tracepoints through their
//      tracefs id, kprobes/kretprobes through the kprobe perf PMU,
//   3. polls the ring buffer, reads the event id from each record's header,
//      and prints the fields per that event's layout.
//
// Deliberately low-level: no skeleton, no CO-RE. honeyc produced the
// instructions; this is the userspace ABI that gets them running.

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

// ----------------------------------------------------- tiny manifest reader
//
// The manifest is small and self-produced (see honeyc's `manifest()`), so a
// scan-for-the-key reader is enough. Each section uses a distinct object key
// ("map", "id"/"event", "prog") and sections come in a fixed order, so every
// scan can be bounded by the start of the next section.

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

// Copy the string value of "key": "..." found at or after `from` and before
// `limit` (NULL = end of text). Returns a pointer past the value, or NULL.
// Keys are matched as `"key":` (with the colon) so a value that happens to
// equal a key name — `"type": "tracepoint"` next to the `"tracepoint"` key —
// can never be mistaken for it.
static const char *json_str_in(const char *from, const char *limit, const char *key,
                               char *out, size_t cap) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(from, pat);
    if (!p || (limit && p >= limit)) return NULL;
    p += strlen(pat); // just past the colon
    p = strchr(p, '"');
    if (!p) return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) out[i++] = *p++;
    out[i] = 0;
    return *p == '"' ? p + 1 : NULL;
}

static long json_int_in(const char *from, const char *limit, const char *key, long dflt) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = strstr(from, pat);
    if (!p || (limit && p >= limit)) return dflt;
    return strtol(p + strlen(pat), NULL, 10);
}

// ------------------------------------------------------------- data model

enum kind { K_UINT, K_INT, K_STR, K_BOOL };

struct field {
    char name[32];
    uint32_t offset;
    uint32_t size;
    enum kind kind;
};

#define MAX_FIELDS 32
#define MAX_EVENTS 16
#define MAX_MAPS 16
#define MAX_PROGS 16

struct event {
    char name[32];
    uint32_t size;
    int n_fields;
    struct field fields[MAX_FIELDS];
};

struct program {
    char name[64];
    char type[16];      // tracepoint | kprobe | kretprobe
    char category[64];  // tracepoint
    char tracepoint[64];
    char function[64];  // kprobe / kretprobe
    char hook[64];      // lsm
    char interface[32]; // xdp
    size_t offset;
    size_t insns;
    const char *relocs; // pointer into the manifest text: the "relocs":[...] array
    const char *relocs_end;
};

// ----------------------------------------------------------------- attach

static int read_int_file(const char *path) {
    // tracefs/sysfs files report size 0, so read directly (not via slurp).
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = -1;
    if (fscanf(f, "%d", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static int perf_open(struct perf_event_attr *attr) {
    // pid = -1, cpu = 0: any process, one CPU. PERF_EVENT_IOC_SET_BPF binds
    // the program to the hook itself, so this one event covers every CPU.
    return syscall(__NR_perf_event_open, attr, -1, 0, -1, 0);
}

static int attach_tracepoint(const char *cat, const char *name, int prog_fd) {
    char path[256];
    snprintf(path, sizeof path, "/sys/kernel/tracing/events/%s/%s/id", cat, name);
    int id = read_int_file(path);
    if (id < 0) {
        fprintf(stderr, "cannot read %s (is tracefs mounted? does the tracepoint exist?)\n", path);
        return -1;
    }
    struct perf_event_attr attr = {0};
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = id;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    int pfd = perf_open(&attr);
    if (pfd < 0) { perror("perf_event_open(tracepoint)"); return -1; }
    if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) { perror("SET_BPF"); return -1; }
    if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) { perror("ENABLE"); return -1; }
    return pfd;
}

// LSM programs are BPF_PROG_TYPE_LSM attached to a BTF function id
// (bpf_lsm_<hook>) via a bpf_link. The program returns 0 to allow, negative
// to deny. Loaded with expected_attach_type BPF_LSM_MAC set at load time,
// which is why LSM is loaded here rather than in the shared loop.
static int load_and_attach_lsm(const char *hook, const char *license,
                               const struct bpf_insn *insns, size_t n, char *log, size_t logsz) {
    static struct btf *vmlinux;
    if (!vmlinux) {
        vmlinux = btf__load_vmlinux_btf();
        if (!vmlinux) { fprintf(stderr, "cannot load vmlinux BTF (needed for LSM)\n"); return -1; }
    }
    char sym[96];
    snprintf(sym, sizeof sym, "bpf_lsm_%s", hook);
    int btf_id = btf__find_by_name_kind(vmlinux, sym, BTF_KIND_FUNC);
    if (btf_id < 0) {
        fprintf(stderr, "LSM hook `%s` not found (looked for `%s` in BTF; is CONFIG_BPF_LSM on and the hook name right?)\n", hook, sym);
        return -1;
    }
    LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_LSM_MAC,
                .attach_btf_id = btf_id, .log_buf = log, .log_size = logsz, .log_level = 1);
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_LSM, "honeylsm", license, insns, n, &opts);
    if (prog_fd < 0) {
        fprintf(stderr, "lsm:%s: verifier rejected the program (%s):\n%s\n", hook, strerror(-prog_fd), log);
        return -1;
    }
    int link = bpf_link_create(prog_fd, 0, BPF_LSM_MAC, NULL);
    if (link < 0) {
        fprintf(stderr, "lsm:%s: bpf_link_create failed (%s); is `bpf` in the kernel's active LSM list?\n", hook, strerror(-link));
        return -1;
    }
    return prog_fd;
}

// XDP programs attach to a network interface, not to a perf event, and they
// stay attached after the loader exits unless detached. Generic ("skb") mode
// works on any device, including veth and loopback, at the cost of running
// after the skb is built rather than in the driver.
static int g_xdp_ifindex[MAX_PROGS];
static int g_xdp_count;
static volatile sig_atomic_t g_stop;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static int attach_xdp(const char *interface, int prog_fd) {
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "xdp: no interface named `%s`\n", interface);
        return -1;
    }
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err < 0) {
        fprintf(stderr, "xdp: attach to %s (ifindex %d) failed: %s\n", interface, ifindex, strerror(-err));
        if (-err == EBUSY) fprintf(stderr, "  (another XDP program is already attached there)\n");
        return -1;
    }
    g_xdp_ifindex[g_xdp_count++] = ifindex;
    return 0;
}

static void detach_all_xdp(void) {
    for (int i = 0; i < g_xdp_count; i++)
        bpf_xdp_detach(g_xdp_ifindex[i], XDP_FLAGS_SKB_MODE, NULL);
}

// kprobes attach through the "kprobe" perf PMU: its numeric type comes from
// sysfs, the function name goes in config1, and the retprobe flag is a
// config bit whose position sysfs also tells us (usually bit 0).
static int attach_kprobe(const char *function, int retprobe, int prog_fd) {
    int pmu = read_int_file("/sys/bus/event_source/devices/kprobe/type");
    if (pmu < 0) {
        fprintf(stderr, "kernel has no kprobe perf PMU (/sys/bus/event_source/devices/kprobe)\n");
        return -1;
    }
    int retbit = 0;
    FILE *f = fopen("/sys/bus/event_source/devices/kprobe/format/retprobe", "r");
    if (f) {
        if (fscanf(f, "config:%d", &retbit) != 1) retbit = 0;
        fclose(f);
    }
    struct perf_event_attr attr = {0};
    attr.type = pmu;
    attr.size = sizeof(attr);
    attr.config = retprobe ? (1ULL << retbit) : 0;
    attr.config1 = (uint64_t)(uintptr_t)function;
    attr.config2 = 0;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    int pfd = perf_open(&attr);
    if (pfd < 0) {
        fprintf(stderr, "perf_event_open(%s %s): %s\n", retprobe ? "kretprobe" : "kprobe",
                function, strerror(errno));
        if (errno == ENOENT) fprintf(stderr, "  (is `%s` in /proc/kallsyms on this kernel?)\n", function);
        return -1;
    }
    if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) { perror("SET_BPF"); return -1; }
    if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) { perror("ENABLE"); return -1; }
    return pfd;
}

// ----------------------------------------------------------- event printing

struct ctx {
    struct event *events;
    int n_events;
    uint32_t header;
    int json;
};

static int on_event(void *vctx, void *data, size_t len) {
    struct ctx *c = vctx;
    if (len < c->header) return 0;
    uint32_t id;
    memcpy(&id, data, 4);
    if (id >= (uint32_t)c->n_events) {
        printf("<unknown event id %u>\n", id);
        return 0;
    }
    struct event *ev = &c->events[id];
    if (len < c->header + ev->size) return 0;
    const uint8_t *rec = (const uint8_t *)data + c->header;

    if (c->json) {
        printf("{\"event\":\"%s\"", ev->name);
        for (int i = 0; i < ev->n_fields; i++) {
            struct field *f = &ev->fields[i];
            const uint8_t *p = rec + f->offset;
            printf(",\"%s\":", f->name);
            switch (f->kind) {
            case K_UINT: { uint64_t v = 0; memcpy(&v, p, f->size); printf("%llu", (unsigned long long)v); break; }
            case K_INT:  { int64_t v = 0; memcpy(&v, p, f->size); if (f->size == 4) v = (int32_t)v; printf("%lld", (long long)v); break; }
            case K_BOOL: printf("%s", *p ? "true" : "false"); break;
            case K_STR:
                putchar('"');
                for (uint32_t j = 0; j < f->size && p[j]; j++) {
                    unsigned char ch = p[j];
                    if (ch == '"' || ch == '\\') { putchar('\\'); putchar(ch); }
                    else if (ch == '\n') { putchar('\\'); putchar('n'); }
                    else if (ch == '\t') { putchar('\\'); putchar('t'); }
                    else if (ch < 0x20) printf("\\u%04x", ch);
                    else putchar(ch);
                }
                putchar('"');
                break;
            }
        }
        printf("}\n");
        fflush(stdout);
        return 0;
    }

    printf("%-14s", ev->name);
    for (int i = 0; i < ev->n_fields; i++) {
        struct field *f = &ev->fields[i];
        const uint8_t *p = rec + f->offset;
        printf("  %s=", f->name);
        switch (f->kind) {
        case K_UINT: { uint64_t v = 0; memcpy(&v, p, f->size); printf("%llu", (unsigned long long)v); break; }
        case K_INT:  { int64_t v = 0; memcpy(&v, p, f->size); if (f->size == 4) v = (int32_t)v; printf("%lld", (long long)v); break; }
        case K_BOOL: printf("%s", *p ? "true" : "false"); break;
        case K_STR:  printf("%.*s", (int)f->size, (const char *)p); break;
        }
    }
    printf("\n");
    fflush(stdout);
    return 0;
}

// ----------------------------------------------------- map fd relocation

// Resolve struct.field byte offset from the running kernel's BTF, so a probe
// compiled against one kernel's layout still reads the right bytes here.
static struct btf *g_vmlinux;
static long btf_field_offset(const char *struct_name, const char *field) {
    if (!g_vmlinux) {
        g_vmlinux = btf__load_vmlinux_btf();
        if (!g_vmlinux) return -1;
    }
    int sid = btf__find_by_name_kind(g_vmlinux, struct_name, BTF_KIND_STRUCT);
    if (sid < 0) sid = btf__find_by_name_kind(g_vmlinux, struct_name, BTF_KIND_UNION);
    if (sid < 0) return -1;
    const struct btf_type *t = btf__type_by_id(g_vmlinux, sid);
    const struct btf_member *m = btf_members(t);
    for (int i = 0; i < btf_vlen(t); i++) {
        const char *mn = btf__name_by_offset(g_vmlinux, m[i].name_off);
        if (mn && strcmp(mn, field) == 0) return btf_member_bit_offset(t, i) / 8;
    }
    return -1;
}

// Rewrite each field-offset relocation's immediate (the imm of the `add`
// instruction at its slot) to the offset resolved from this kernel's BTF.
static int apply_relocs(uint8_t *insns, size_t bytes, struct program *pr) {
    if (!pr->relocs) return 0;
    const char *p = pr->relocs;
    const char *limit = pr->relocs_end;
    while ((p = strstr(p, "\"slot\":")) != NULL) {
        if (limit && p >= limit) break;
        long slot = json_int_in(p, limit, "slot", -1);
        char sname[64] = "", field[64] = "";
        json_str_in(p, limit, "struct", sname, sizeof sname);
        json_str_in(p, limit, "field", field, sizeof field);
        p += 7;
        if (slot < 0) continue;
        size_t at = (size_t)slot * 8;
        if (at + 8 > bytes) { fprintf(stderr, "reloc slot %ld out of range\n", slot); return -1; }
        long off = btf_field_offset(sname, field);
        if (off < 0) {
            fprintf(stderr, "cannot resolve %s.%s in this kernel's BTF\n", sname, field);
            return -1;
        }
        int32_t imm = (int32_t)off;
        memcpy(insns + at + 4, &imm, 4);
    }
    return 0;
}

// `ld64 rN, map_fd(i)` is a 16-byte LD_IMM64 (opcode 0x18) with src-reg
// nibble 1 (BPF_PSEUDO_MAP_FD) and imm = map index. Rewrite to the real fd.
static void relocate_map_fds(uint8_t *insns, size_t bytes, const int *fds, int nfds) {
    for (size_t i = 0; i + 8 <= bytes; ) {
        uint8_t opcode = insns[i];
        uint8_t src = insns[i + 1] >> 4;
        if (opcode == 0x18) {
            if (src == 1 && i + 16 <= bytes) {
                int32_t idx;
                memcpy(&idx, insns + i + 4, 4);
                if (idx >= 0 && idx < nfds) memcpy(insns + i + 4, &fds[idx], 4);
                else fprintf(stderr, "bytecode references map index %d but only %d maps exist\n", idx, nfds);
            }
            i += 16;
        } else {
            i += 8;
        }
    }
}

int main(int argc, char **argv) {
    int json = 0;
    int a = 1;
    if (a < argc && strcmp(argv[a], "--json") == 0) { json = 1; a++; }
    if (argc - a != 2) {
        fprintf(stderr, "usage: %s [--json] <program.bin> <program.json>\n", argv[0]);
        return 2;
    }

    size_t code_len = 0;
    uint8_t *code = (uint8_t *)slurp(argv[a], &code_len);
    char *man = slurp(argv[a + 1], NULL);
    if (!code || !man) return 1;
    if (code_len % 8 != 0) {
        fprintf(stderr, "bytecode length %zu is not a multiple of 8\n", code_len);
        return 1;
    }

    // ---- top-level scalars
    char license[16] = "GPL", arch[16] = "";
    json_str_in(man, NULL, "license", license, sizeof license);
    json_str_in(man, NULL, "arch", arch, sizeof arch);
    long ringbuf_bytes = json_int_in(man, NULL, "ringbuf_bytes", 1 << 16);
    long header = json_int_in(man, NULL, "record_header", 8);

    struct utsname un;
    if (uname(&un) == 0 && arch[0] && strcmp(un.machine, arch) != 0) {
        fprintf(stderr, "warning: program compiled for %s but this kernel is %s; kprobe argument offsets will be wrong\n",
                arch, un.machine);
    }

    const char *maps_sec = strstr(man, "\"maps\":");
    const char *events_sec = strstr(man, "\"events\":");
    const char *progs_sec = strstr(man, "\"programs\":");
    if (!maps_sec || !events_sec || !progs_sec) {
        fprintf(stderr, "manifest is missing maps/events/programs sections\n");
        return 1;
    }

    // ---- events
    static struct event events[MAX_EVENTS];
    int n_events = 0;
    for (const char *p = strstr(events_sec, "\"id\":"); p && p < progs_sec && n_events < MAX_EVENTS;) {
        struct event *ev = &events[n_events];
        const char *next = strstr(p + 5, "\"id\":");
        const char *limit = (next && next < progs_sec) ? next : progs_sec;
        json_str_in(p, limit, "event", ev->name, sizeof ev->name);
        ev->size = json_int_in(p, limit, "size", 0);
        ev->n_fields = 0;
        for (const char *fp = strstr(p, "\"name\":"); fp && fp < limit && ev->n_fields < MAX_FIELDS;) {
            struct field *f = &ev->fields[ev->n_fields];
            char kind[16] = "uint";
            const char *after = json_str_in(fp, limit, "name", f->name, sizeof f->name);
            if (!after) break;
            f->offset = json_int_in(fp, limit, "offset", 0);
            f->size = json_int_in(fp, limit, "size", 0);
            json_str_in(fp, limit, "kind", kind, sizeof kind);
            f->kind = strcmp(kind, "str") == 0 ? K_STR
                    : strcmp(kind, "bool") == 0 ? K_BOOL
                    : strcmp(kind, "int") == 0 ? K_INT : K_UINT;
            ev->n_fields++;
            fp = strstr(after, "\"name\":");
        }
        n_events++;
        p = (next && next < progs_sec) ? next : NULL;
    }

    // ---- programs
    static struct program progs[MAX_PROGS];
    int n_progs = 0;
    for (const char *p = strstr(progs_sec, "\"prog\":"); p && n_progs < MAX_PROGS;) {
        struct program *pr = &progs[n_progs];
        const char *next = strstr(p + 7, "\"prog\":");
        json_str_in(p, next, "prog", pr->name, sizeof pr->name);
        json_str_in(p, next, "type", pr->type, sizeof pr->type);
        json_str_in(p, next, "category", pr->category, sizeof pr->category);
        json_str_in(p, next, "tracepoint", pr->tracepoint, sizeof pr->tracepoint);
        json_str_in(p, next, "function", pr->function, sizeof pr->function);
        json_str_in(p, next, "hook", pr->hook, sizeof pr->hook);
        json_str_in(p, next, "interface", pr->interface, sizeof pr->interface);
        pr->offset = json_int_in(p, next, "offset", 0);
        pr->insns = json_int_in(p, next, "insns", 0);
        pr->relocs = strstr(p, "\"relocs\":");
        if (pr->relocs && next && pr->relocs > next) pr->relocs = NULL;
        pr->relocs_end = next;
        if (pr->offset + pr->insns * 8 > code_len) {
            fprintf(stderr, "program %s: offset/insns exceed the bytecode file\n", pr->name);
            return 1;
        }
        n_progs++;
        p = next;
    }
    if (n_progs == 0) { fprintf(stderr, "manifest has no programs\n"); return 1; }

    // ---- 1. maps
    int fds[MAX_MAPS];
    int nfds = 0;
    int rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "events", 0, 0, ringbuf_bytes, NULL);
    if (rb_fd < 0) { fprintf(stderr, "bpf_map_create(ringbuf): %s\n", strerror(-rb_fd)); return 1; }
    fds[nfds++] = rb_fd;
    for (const char *p = strstr(maps_sec, "\"map\":"); p && p < events_sec && nfds < MAX_MAPS;) {
        char mname[32], mkind[16] = "hash";
        const char *next = strstr(p + 6, "\"map\":");
        const char *limit = (next && next < events_sec) ? next : events_sec;
        json_str_in(p, limit, "map", mname, sizeof mname);
        json_str_in(p, limit, "kind", mkind, sizeof mkind);
        long ks = json_int_in(p, limit, "key_size", 4);
        long vs = json_int_in(p, limit, "value_size", 8);
        long me = json_int_in(p, limit, "max_entries", 1);
        enum bpf_map_type t = strcmp(mkind, "array") == 0 ? BPF_MAP_TYPE_ARRAY : BPF_MAP_TYPE_HASH;
        int fd = bpf_map_create(t, mname, ks, vs, me, NULL);
        if (fd < 0) { fprintf(stderr, "bpf_map_create(%s): %s\n", mname, strerror(-fd)); return 1; }
        fprintf(stderr, "map %d: %s (%s, key %ld, value %ld, max %ld) fd %d\n", nfds, mname, mkind, ks, vs, me, fd);
        fds[nfds++] = fd;
        p = (next && next < events_sec) ? next : NULL;
    }

    // ---- 2. load + attach each program
    static char log[256 * 1024];
    for (int i = 0; i < n_progs; i++) {
        struct program *pr = &progs[i];
        uint8_t *insns = code + pr->offset;
        size_t bytes = pr->insns * 8;
        relocate_map_fds(insns, bytes, fds, nfds);
        if (apply_relocs(insns, bytes, pr) < 0) return 1;

        if (strcmp(pr->type, "xdp") == 0) {
            LIBBPF_OPTS(bpf_prog_load_opts, xopts, .log_buf = log, .log_size = sizeof log, .log_level = 1);
            int fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "honeyxdp", license, (const struct bpf_insn *)insns, pr->insns, &xopts);
            if (fd < 0) {
                fprintf(stderr, "%s: verifier rejected the program (%s):\n%s\n", pr->name, strerror(-fd), log);
                return 1;
            }
            if (attach_xdp(pr->interface, fd) < 0) return 1;
            fprintf(stderr, "%s: loaded (%zu insns, fd %d) and attached (generic mode)\n", pr->name, pr->insns, fd);
            continue;
        }

        if (strcmp(pr->type, "lsm") == 0) {
            int fd = load_and_attach_lsm(pr->hook, license, (const struct bpf_insn *)insns, pr->insns, log, sizeof log);
            if (fd < 0) return 1;
            fprintf(stderr, "%s: loaded (%zu insns, fd %d) and attached\n", pr->name, pr->insns, fd);
            continue;
        }

        int is_kprobe = strcmp(pr->type, "kprobe") == 0 || strcmp(pr->type, "kretprobe") == 0;
        enum bpf_prog_type pt = is_kprobe ? BPF_PROG_TYPE_KPROBE : BPF_PROG_TYPE_TRACEPOINT;
        LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_buf = log, .log_size = sizeof log, .log_level = 1);
        char short_name[16];
        snprintf(short_name, sizeof short_name, "honey%d", i);
        int prog_fd = bpf_prog_load(pt, short_name, license, (const struct bpf_insn *)insns, pr->insns, &opts);
        if (prog_fd < 0) {
            fprintf(stderr, "%s: verifier rejected the program (%s):\n%s\n", pr->name, strerror(-prog_fd), log);
            return 1;
        }
        int pfd;
        if (is_kprobe)
            pfd = attach_kprobe(pr->function, strcmp(pr->type, "kretprobe") == 0, prog_fd);
        else
            pfd = attach_tracepoint(pr->category, pr->tracepoint, prog_fd);
        if (pfd < 0) return 1;
        fprintf(stderr, "%s: loaded (%zu insns, fd %d) and attached\n", pr->name, pr->insns, prog_fd);
        // pfd intentionally kept open: closing it would detach the program.
    }

    // ---- 3. poll
    struct ctx c = { .events = events, .n_events = n_events, .header = (uint32_t)header, .json = json };
    struct ring_buffer *rb = ring_buffer__new(rb_fd, on_event, &c, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); return 1; }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "waiting for events, Ctrl-C to stop...\n");
    while (!g_stop) {
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "poll: %s\n", strerror(-err)); break; }
    }
    // XDP programs outlive their fds; take them off the interfaces.
    detach_all_xdp();
    if (g_xdp_count) fprintf(stderr, "detached %d xdp program(s)\n", g_xdp_count);
    return 0;
}
