/* Local replay harness for CVE-2014-7825 (ftrace_syscall_exit).
 *
 * Compiles the verbatim vulnerable (before.c), patched (after.c) and derived
 * ineffective (ineffective.c) / equivalent (equivalent.c) copies of the
 * function and runs one <variant, syscall_nr> combination per invocation.
 *
 * The out-of-bounds access under test is the array read
 *     tr->exit_syscall_files[syscall_nr]
 * which occurs when syscall_nr >= NR_syscalls (no upper-bound check before
 * the fix). `rcu_dereference_sched` is stubbed as a macro that records the
 * address being dereferenced (g_read_ptr), so an out-of-bounds read is
 * observed as read_index >= NR_syscalls without needing ASan.
 *
 * Kernel helpers (trace_get_syscall_nr, ftrace_trigger_soft_disabled,
 * syscall_nr_to_meta, local_save_flags, preempt_count, ...) are stubbed to a
 * minimal local contract. `NR_syscalls` is shrunk to 16 for the unit replay;
 * the upper-bound logic is unchanged.
 *
 * Usage:
 *   ftrace_syscall_exit_harness.exe <variant:before|after|ineffective-01|equivalent-01> <syscall_nr>
 *
 * stdout carries one machine-readable summary line; stderr a short trace.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#define NR_syscalls 16

/* ---- minimal kernel types ---- */
struct ftrace_event_file { int dummy; };
struct trace_event { int type; };
struct ftrace_event_call { struct trace_event event; };
struct syscall_metadata { struct ftrace_event_call *exit_event; };
struct syscall_trace_exit { int nr; long ret; };
struct ring_buffer_event { int dummy; };
struct ring_buffer { int dummy; };
struct trace_buffer { struct ring_buffer *buffer; };
struct pt_regs { int dummy; };
struct task_struct { int dummy; };

/* tr->exit_syscall_files has NR_syscalls pointers; canary[0] sits exactly at
 * index NR_syscalls (first out-of-bounds cell), padding keeps index NR_syscalls+1
 * inside the struct so the replay does not read outside the object. */
struct trace_array {
    struct ftrace_event_file *exit_syscall_files[NR_syscalls];
    uint64_t canary[1];
    uint64_t padding[4];
    struct trace_buffer trace_buffer;
};

/* ---- kernel symbols / stubs ---- */
static struct task_struct *current;
static int g_inject_nr = 0;

static void *g_read_ptr;               /* address dereferenced by rcu_dereference_sched */
#define rcu_dereference_sched(p) (g_read_ptr = (void *)(&(p)), (p))

static int trace_get_syscall_nr(struct task_struct *t, struct pt_regs *r) {
    (void)t; (void)r;
    return g_inject_nr;
}

static int ftrace_trigger_soft_disabled(struct ftrace_event_file *f) {
    (void)f;
    return 0;   /* not disabled -> continue toward syscall_nr_to_meta */
}

static struct syscall_metadata *syscall_nr_to_meta(int nr) {
    (void)nr;
    return NULL;  /* stop right after the observed array read */
}

/* never reached in this harness (sys_data is NULL), but declared to keep the
 * verbatim function body linkable */
static void local_save_flags(unsigned long flags) { (void)flags; }
static int preempt_count(void) { return 0; }
static struct ring_buffer_event *trace_buffer_lock_reserve(
        struct ring_buffer *b, int type, unsigned long len,
        unsigned long flags, int pc) { (void)b;(void)type;(void)len;(void)flags;(void)pc; return NULL; }
static void *ring_buffer_event_data(struct ring_buffer_event *e) { (void)e; return NULL; }
static long syscall_get_return_value(struct task_struct *t, struct pt_regs *r) { (void)t;(void)r; return 0; }
static void event_trigger_unlock_commit(struct ftrace_event_file *f, struct ring_buffer *b,
        struct ring_buffer_event *e, void *entry, unsigned long flags, int pc) {
    (void)f;(void)b;(void)e;(void)entry;(void)flags;(void)pc;
}

#include "before.c"
#include "after.c"
#include "ineffective.c"
#include "equivalent.c"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <variant:before|after|ineffective-01|equivalent-01> <syscall_nr>\n", argv[0]);
        return 2;
    }
    const char *variant = argv[1];
    int nr = atoi(argv[2]);

    void (*fn)(void *, struct pt_regs *, long) = NULL;
    if (strcmp(variant, "before") == 0) fn = ftrace_syscall_exit_before;
    else if (strcmp(variant, "after") == 0) fn = ftrace_syscall_exit_after;
    else if (strcmp(variant, "ineffective-01") == 0) fn = ftrace_syscall_exit_ineffective;
    else if (strcmp(variant, "equivalent-01") == 0) fn = ftrace_syscall_exit_equivalent;
    else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

    static struct trace_array tr;
    static struct ftrace_event_file files[NR_syscalls];
    static struct task_struct task;
    static struct pt_regs regs;
    memset(&tr, 0, sizeof tr);
    memset(&files, 0, sizeof files);
    for (int i = 0; i < NR_syscalls; i++) tr.exit_syscall_files[i] = &files[i];
    tr.canary[0] = 0xDEADBEEFCAFEBABEULL;   /* index NR_syscalls (first OOB cell) */
    tr.trace_buffer.buffer = NULL;
    current = &task;

    g_inject_nr = nr;
    g_read_ptr = NULL;

    fn(&tr, &regs, 0L);

    long read_index = -1;
    int read_observed = 0;
    int oob_read = 0;
    int intercepted = 0;
    if (g_read_ptr != NULL) {
        read_observed = 1;
        read_index = ((char *)g_read_ptr - (char *)tr.exit_syscall_files) / (long)sizeof(struct ftrace_event_file *);
        oob_read = (read_index < 0 || read_index >= NR_syscalls) ? 1 : 0;
    } else {
        intercepted = 1;
    }
    int canary_intact = (tr.canary[0] == 0xDEADBEEFCAFEBABEULL) ? 1 : 0;

    fprintf(stderr,
            "[%s/nr=%d] read_observed=%d read_index=%ld oob_read=%d intercepted=%d canary_intact=%d\n",
            variant, nr, read_observed, read_index, oob_read, intercepted, canary_intact);

    fprintf(stdout,
            "VARIANT=%s NR=%d READ_OBSERVED=%d READ_INDEX=%ld OOB_READ=%d INTERCEPTED=%d CANARY_INTACT=%d\n",
            variant, nr, read_observed, read_index, oob_read, intercepted, canary_intact);
    return 0;
}
