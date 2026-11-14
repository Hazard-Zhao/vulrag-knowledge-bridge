typedef unsigned int u32;
struct kvm_cpuid_entry2 {u32 function,index,flags,eax,ebx,ecx,edx,padding[3];};
#define E2BIG 7
/* Numeric constants below are local fixture encodings, not Linux ioctl ABI values. */
#define KVM_GET_EMULATED_CPUID 1
#define KVM_CPUID_FLAG_SIGNIFCANT_INDEX 1
#define F(x) 1
static int __do_cpuid_func_emulated(struct kvm_cpuid_entry2 *entry,
				    u32 func, int *nent, int maxnent)
{
	entry->function = func;
	entry->index = 0;
	entry->flags = 0;

	switch (func) {
	case 0:
		entry->eax = 7;
		++*nent;
		break;
	case 1:
		entry->ecx = F(MOVBE);
		++*nent;
		break;
	case 7:
		entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
		entry->eax = 0;
		entry->ecx = F(RDPID);
		++*nent;
	default:
		break;
	}

	return 0;
}
static int __do_cpuid_func(struct kvm_cpuid_entry2*e,u32 f,int*n,int m){return -E2BIG;}static int do_cpuid_func(struct kvm_cpuid_entry2 *entry, u32 func,
			 int *nent, int maxnent, unsigned int type)
{
	if (type == KVM_GET_EMULATED_CPUID)
		return __do_cpuid_func_emulated(entry, func, nent, maxnent);

	return __do_cpuid_func(entry, func, nent, maxnent);
}
static int submit(struct kvm_cpuid_entry2 *array,int *n,int capacity,u32 func){return do_cpuid_func(&array[*n],func,n,capacity,KVM_GET_EMULATED_CPUID);}
#include <stdio.h>
#include <string.h>
int main(void){unsigned fs[]={0,1,7,0x80000000};for(int n=0;n<=4;n++)for(int f=0;f<4;f++){
struct kvm_cpuid_entry2 array[5],sentinel;memset(array,0x5a,sizeof(array));sentinel=array[4];int k=n;
int ret=submit(array,&k,4,fs[f]);int violation=memcmp(&sentinel,&array[4],sizeof(sentinel))!=0;
printf("%d %u %d %d %d\n",n,fs[f],violation,k,ret);}return 0;}
