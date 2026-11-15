/* Local replay harness for CVE-2013-4587 (kvm_vm_ioctl_create_vcpu).
 *
 * Compiles the verbatim vulnerable (before.c), patched (after.c) and derived
 * ineffective (ineffective.c) / equivalent (equivalent.c) copies and runs one
 * <variant, id> combination per invocation.
 *
 * The fix is the input-validation guard `if (id >= KVM_MAX_VCPUS) return
 * -EINVAL;` added at the top. The downstream OOB (vcpu_id later used as an
 * array index elsewhere in KVM) is not reachable from this unit; the harness
 * therefore observes whether the function proceeds to kvm_arch_vcpu_create
 * with an out-of-range id — the necessary condition the guard is meant to
 * block. KVM_MAX_VCPUS is stubbed to 4 for the unit replay (upstream is 1024).
 *
 * Usage:
 *   kvm_vm_ioctl_create_vcpu_harness.exe <variant:before|after|ineffective-01|equivalent-01> <id>
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef uint32_t u32;

#define KVM_MAX_VCPUS 4
#define EINVAL 22
#define EEXIST 17

#define IS_ERR(x) ((long)(x) < 0 && (long)(x) >= -4095L)
#define PTR_ERR(x) ((int)(long)(x))
#define BUG_ON(x) do { if (x) abort(); } while (0)
#define mutex_lock(x) do {} while (0)
#define mutex_unlock(x) do {} while (0)
#define smp_wmb() do {} while (0)
#define atomic_inc(x) do { (*(x))++; } while (0)
#define atomic_read(x) (*(x))
#define kvm_for_each_vcpu(r, v, k) for ((r) = 0, (v) = (struct kvm_vcpu *)0; 0; )

struct kvm_vcpu {
    int vcpu_id;
    int preempt_notifier;
};
struct kvm {
    int lock;
    int online_vcpus;
    struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
};

static struct kvm_vcpu g_vcpu;
static int g_arch_create_called = 0;
static int g_arch_create_id = -1;
static int kvm_preempt_ops;

static struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, u32 id) {
    (void)kvm;
    g_arch_create_called = 1;
    g_arch_create_id = (int)id;
    g_vcpu.vcpu_id = (int)id;
    return &g_vcpu;
}
static int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu) { (void)vcpu; return 0; }
static int kvm_vcpu_compatible(struct kvm_vcpu *vcpu) { (void)vcpu; return 1; }
static void preempt_notifier_init(void *a, void *b) { (void)a; (void)b; }
static void kvm_get_kvm(struct kvm *k) { (void)k; }
static void kvm_put_kvm(struct kvm *k) { (void)k; }
static int create_vcpu_fd(struct kvm_vcpu *vcpu) { (void)vcpu; return 0; }
static void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu) { (void)vcpu; }
static void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu) { (void)vcpu; }

#include "before.c"
#include "after.c"
#include "ineffective.c"
#include "equivalent.c"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <variant:before|after|ineffective-01|equivalent-01> <id>\n", argv[0]);
        return 2;
    }
    const char *variant = argv[1];
    int id = atoi(argv[2]);

    int (*fn)(struct kvm *, u32) = NULL;
    if (strcmp(variant, "before") == 0) fn = kvm_vm_ioctl_create_vcpu_before;
    else if (strcmp(variant, "after") == 0) fn = kvm_vm_ioctl_create_vcpu_after;
    else if (strcmp(variant, "ineffective-01") == 0) fn = kvm_vm_ioctl_create_vcpu_ineffective;
    else if (strcmp(variant, "equivalent-01") == 0) fn = kvm_vm_ioctl_create_vcpu_equivalent;
    else { fprintf(stderr, "unknown variant: %s\n", variant); return 2; }

    struct kvm kvm;
    memset(&kvm, 0, sizeof kvm);
    g_arch_create_called = 0;
    g_arch_create_id = -1;

    int ret = fn(&kvm, (u32)id);

    int guard_bypassed = (g_arch_create_called && id >= KVM_MAX_VCPUS) ? 1 : 0;

    fprintf(stderr,
            "[%s/id=%d] ret=%d arch_create_called=%d arch_create_id=%d guard_bypassed=%d\n",
            variant, id, ret, g_arch_create_called, g_arch_create_id, guard_bypassed);

    fprintf(stdout,
            "VARIANT=%s ID=%d RET=%d ARCH_CREATE_CALLED=%d ARCH_CREATE_ID=%d GUARD_BYPASSED=%d\n",
            variant, id, ret, g_arch_create_called, g_arch_create_id, guard_bypassed);
    return 0;
}
