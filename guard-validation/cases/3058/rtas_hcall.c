/* Local replay harness for CVE-2021-37576 (kvmppc_rtas_hcall, "RTAS").
 *
 * Compiles the verbatim vulnerable (before.c), patched (after.c) and derived
 * ineffective (ineffective.c) copies of the function and runs one
 * <variant, nargs> combination per invocation.
 *
 * Kernel symbols (structs, list, mutex, kvm_read_guest, ...) are stubbed to a
 * minimal local contract. struct rtas_args keeps the upstream args[16] array,
 * and the harness adds a canary[2] immediately after it so that writes to
 * args[16] / args[17] land in observable canary cells instead of corrupting
 * the trailing `rets` pointer field.
 *
 * This is a unit-level replay, not ASan and not a real KVM guest.
 *
 * Usage:
 *   rtas_hcall.exe <variant:before|after|ineffective> <nargs:15|16|17>
 *
 * stdout carries one machine-readable summary line; stderr carries a short
 * trace of the handler invocation and the observed pointer offset.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

typedef uint32_t __be32;
typedef __be32 rtas_arg_t;
typedef uint64_t gpa_t;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define KVM_PAM ((gpa_t)~0ULL)
#define EINVAL 22
#define ENOENT 2
/* harness feeds host-order values; endianness is not under test */
#define be32_to_cpu(x) (x)

#define MATCH_TOKEN 0x1234u
#define CANARY 0xDEADBEEFu
#define MAGIC  0x5A17C0DEu

struct list_head { struct list_head *next, *prev; };

struct rtas_args {
    __be32 token;
    __be32 nargs;
    __be32 nret;
    rtas_arg_t args[16];     /* valid 0..15; ARRAY_SIZE(args.args) == 16 */
    rtas_arg_t canary[2];    /* harness-only: observe writes to args[16], args[17] */
    rtas_arg_t *rets;        /* upstream "pointer to return values in args[]" */
};

struct kvm_vcpu;

struct rtas_handler {
    void (*handler)(struct kvm_vcpu *vcpu, struct rtas_args *args);
};

struct rtas_token_definition {
    struct list_head list;
    struct rtas_handler *handler;
    __be32 token;
};

struct kvm_arch {
    int rtas_token_lock;               /* mutex stub */
    struct list_head rtas_tokens;
};

struct kvm {
    int srcu;                          /* srcu struct stub (addressable member) */
    struct kvm_arch arch;
};

struct kvm_vcpu {
    struct kvm *kvm;
    int srcu_idx;
};

/* ---- minimal list helpers ---- */
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#define list_for_each_entry(pos, head, member) \
    for (pos = container_of((head)->next, struct rtas_token_definition, member); \
         &pos->member != (head); \
         pos = container_of(pos->member.next, struct rtas_token_definition, member))

static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static void list_add(struct list_head *n, struct list_head *head) {
    n->next = head->next; n->prev = head;
    head->next->prev = n; head->next = n;
}

/* ---- kernel stubs ---- */
static gpa_t kvmppc_get_gpr(struct kvm_vcpu *vcpu, int reg) { (void)vcpu; (void)reg; return 0; }
static int srcu_read_lock(int *sp) { (void)sp; return 0; }
static void srcu_read_unlock(int *sp, int idx) { (void)sp; (void)idx; }
static void mutex_lock(int *m) { (void)m; }
static void mutex_unlock(int *m) { (void)m; }

static struct rtas_args g_guest;

static int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, size_t len) {
    (void)kvm; (void)gpa;
    memcpy(data, &g_guest, len < sizeof(g_guest) ? len : sizeof(g_guest));
    return 0;
}
static int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data, size_t len) {
    (void)kvm; (void)gpa;
    memcpy(&g_guest, data, len < sizeof(g_guest) ? len : sizeof(g_guest));
    return 0;
}

/* ---- handler under test: writes rets[0] (the dangerous write) ---- */
static int g_handler_entered = 0;
static int g_rets_index = -1;
static rtas_arg_t g_rets_written = 0;

static void test_handler(struct kvm_vcpu *vcpu, struct rtas_args *args) {
    (void)vcpu;
    g_handler_entered = 1;
    g_rets_index = (int)(((char *)args->rets - (char *)args->args) / (int)sizeof(rtas_arg_t));
    if (args->rets) {
        args->rets[0] = MAGIC;   /* OOB write if g_rets_index >= 16 */
        g_rets_written = MAGIC;
    }
}

#include "before.c"
#include "after.c"
#include "ineffective.c"
#include "equivalent.c"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <variant:before|after|ineffective-01|equivalent-01> <nargs>\n", argv[0]);
        return 2;
    }
    const char *variant = argv[1];
    int nargs = atoi(argv[2]);

    int (*fn)(struct kvm_vcpu *) = NULL;
    if (strcmp(variant, "before") == 0) fn = kvmppc_rtas_hcall_before;
    else if (strcmp(variant, "after") == 0) fn = kvmppc_rtas_hcall_after;
    else if (strcmp(variant, "ineffective-01") == 0) fn = kvmppc_rtas_hcall_ineffective;
    else if (strcmp(variant, "equivalent-01") == 0) fn = kvmppc_rtas_hcall_equivalent;
    else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

    /* minimal vcpu + one matching RTAS token */
    struct kvm kvm;
    struct kvm_vcpu vcpu;
    struct rtas_handler h = { test_handler };
    struct rtas_token_definition tok;
    memset(&kvm, 0, sizeof kvm);
    memset(&vcpu, 0, sizeof vcpu);
    INIT_LIST_HEAD(&kvm.arch.rtas_tokens);
    tok.token = MATCH_TOKEN;
    tok.handler = &h;
    list_add(&tok.list, &kvm.arch.rtas_tokens);
    vcpu.kvm = &kvm;

    /* prepare guest rtas args in host byte order */
    memset(&g_guest, 0, sizeof g_guest);
    g_guest.token = MATCH_TOKEN;
    g_guest.nargs = (__be32)nargs;
    g_guest.nret = 1;
    g_guest.canary[0] = CANARY;
    g_guest.canary[1] = CANARY;
    g_guest.rets = NULL;

    rtas_arg_t canary0_before = g_guest.canary[0];
    rtas_arg_t canary1_before = g_guest.canary[1];

    int ret = fn(&vcpu);

    fprintf(stderr,
            "[%s/nargs=%d] handler_entered=%d rets_index=%d rets_written=0x%08x ret=%d\n",
            variant, nargs, g_handler_entered, g_rets_index,
            (unsigned)g_rets_written, ret);

    int oob_write = g_handler_entered && g_rets_index >= 16;
    fprintf(stdout,
            "VARIANT=%s NARGS=%d RET=%d HANDLER_ENTERED=%d RETS_INDEX=%d "
            "CANARY0_BEFORE=0x%08x CANARY0_AFTER=0x%08x CANARY1_BEFORE=0x%08x CANARY1_AFTER=0x%08x "
            "ARGS15_AFTER=0x%08x OOB_WRITE=%d\n",
            variant, nargs, ret, g_handler_entered, g_rets_index,
            (unsigned)canary0_before, (unsigned)g_guest.canary[0],
            (unsigned)canary1_before, (unsigned)g_guest.canary[1],
            (unsigned)g_guest.args[15], oob_write);
    return 0;
}
