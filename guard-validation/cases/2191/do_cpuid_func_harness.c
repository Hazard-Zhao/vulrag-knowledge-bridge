/* Local replay harness for CVE-2019-19332 (do_cpuid_func).
 *
 * Compiles the verbatim vulnerable (before.c), patched (after.c) and derived
 * ineffective (ineffective.c) / equivalent (equivalent.c) copies and runs one
 * <variant, *nent> combination per invocation.
 *
 * do_cpuid_func is the KVM cpuid front gate: the fix rejects `*nent >= maxnent`
 * before delegating to __do_cpuid_func / __do_cpuid_func_emulated, which write
 * `entry[(*nent)++]`. The harness stubs those callees to perform the dangerous
 * write and record the index, so a guard bypass is observed as a write to
 * entry[maxnent] (first out-of-bounds cell), backed by a canary entry.
 *
 * Usage:
 *   do_cpuid_func_harness.exe <variant:before|after|ineffective-01|equivalent-01> <nent>
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef uint32_t u32;

#define KVM_GET_EMULATED_CPUID 1
#define E2BIG 7
#define MAGIC_FUNC 0xC0DE0001u
#define CANARY_FUNC 0xDEADBEEFu

struct kvm_cpuid_entry2 {
    u32 function, index, flags, eax, ebx, ecx, edx;
};

static struct kvm_cpuid_entry2 g_entries[6];  /* maxnent=4 + 2 canary cells */
static int g_inner_called = 0;
static int g_write_index = -1;

static struct kvm_cpuid_entry2 make_entry(void) {
    struct kvm_cpuid_entry2 e;
    e.function = MAGIC_FUNC; e.index = 0; e.flags = 0;
    e.eax = 1; e.ebx = 2; e.ecx = 3; e.edx = 4;
    return e;
}

static int __do_cpuid_func(struct kvm_cpuid_entry2 *entry, u32 func, int *nent, int maxnent) {
    (void)func; (void)maxnent;
    g_inner_called = 1;
    g_write_index = *nent;
    entry[(*nent)++] = make_entry();   /* OOB write if g_write_index >= maxnent */
    return 0;
}

static int __do_cpuid_func_emulated(struct kvm_cpuid_entry2 *entry, u32 func, int *nent, int maxnent) {
    return __do_cpuid_func(entry, func, nent, maxnent);
}

#include "before.c"
#include "after.c"
#include "ineffective.c"
#include "equivalent.c"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <variant:before|after|ineffective-01|equivalent-01> <nent>\n", argv[0]);
        return 2;
    }
    const char *variant = argv[1];
    int nent_in = atoi(argv[2]);

    int (*fn)(struct kvm_cpuid_entry2 *, u32, int *, int, unsigned int) = NULL;
    if (strcmp(variant, "before") == 0) fn = do_cpuid_func_before;
    else if (strcmp(variant, "after") == 0) fn = do_cpuid_func_after;
    else if (strcmp(variant, "ineffective-01") == 0) fn = do_cpuid_func_ineffective;
    else if (strcmp(variant, "equivalent-01") == 0) fn = do_cpuid_func_equivalent;
    else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

    const int maxnent = 4;
    memset(g_entries, 0, sizeof g_entries);
    for (int i = 0; i < 6; i++) g_entries[i].function = CANARY_FUNC;
    g_inner_called = 0;
    g_write_index = -1;

    int nent = nent_in;
    int ret = fn(g_entries, 0xC0DE, &nent, maxnent, 0);

    int oob_write = (g_inner_called && g_write_index >= maxnent) ? 1 : 0;
    int canary_changed = (g_entries[maxnent].function != CANARY_FUNC) ? 1 : 0;

    fprintf(stderr,
            "[%s/nent=%d] ret=%d inner_called=%d write_index=%d oob_write=%d canary_changed=%d\n",
            variant, nent_in, ret, g_inner_called, g_write_index, oob_write, canary_changed);

    fprintf(stdout,
            "VARIANT=%s NENT=%d RET=%d INNER_CALLED=%d WRITE_INDEX=%d OOB_WRITE=%d CANARY_CHANGED=%d\n",
            variant, nent_in, ret, g_inner_called, g_write_index, oob_write, canary_changed);
    return 0;
}
