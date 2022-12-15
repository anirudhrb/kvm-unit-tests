#include "libcflat.h"
#include "processor.h"
#include "alloc_page.h"
#include "vm.h"
#include "vmalloc.h"
#include "desc.h"
#include "vmx.h"
#include "msr.h"
#include "smp.h"
#include "apic.h"

extern struct descriptor_table_ptr gdt_descr;
extern struct descriptor_table_ptr idt_descr;

extern void *entry_sysenter;
extern void *vmx_return;
extern void *guest_entry;

u64 *bsp_vmxon_region;
u32 ctrl_pin, ctrl_enter, ctrl_exit, ctrl_cpu[2];
struct vmcs *vmcs_root;

u64 guest_stack_top, guest_syscall_stack_top;
u32 vpid_cnt;
bool launched;

union vmx_basic basic;
union vmx_ctrl_msr ctrl_pin_rev;
union vmx_ctrl_msr ctrl_cpu_rev[2];
union vmx_ctrl_msr ctrl_exit_rev;
union vmx_ctrl_msr ctrl_enter_rev;
union vmx_ept_vpid  ept_vpid;

/* entry_sysenter */
asm(
	".align	4, 0x90\n\t"
	".globl	entry_sysenter\n\t"
	"entry_sysenter:\n\t"
	"	and	$0xf, %rax\n\t"
	"	mov	%rax, %rdi\n\t"
	"	call	syscall_handler\n\t"
	"	vmresume\n\t"
);

static void __attribute__((__used__)) syscall_handler(u64 syscall_no)
{
	printf("Reached syscall_handler");
}

static void init_vmx_caps(void)
{
	basic.val = rdmsr(MSR_IA32_VMX_BASIC);
	ctrl_pin_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PIN
			: MSR_IA32_VMX_PINBASED_CTLS);
	ctrl_exit_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_EXIT
			: MSR_IA32_VMX_EXIT_CTLS);
	ctrl_enter_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_ENTRY
			: MSR_IA32_VMX_ENTRY_CTLS);
	ctrl_cpu_rev[0].val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PROC
			: MSR_IA32_VMX_PROCBASED_CTLS);
	if ((ctrl_cpu_rev[0].clr & CPU_SECONDARY) != 0)
		ctrl_cpu_rev[1].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	else
		ctrl_cpu_rev[1].val = 0;
	if ((ctrl_cpu_rev[1].clr & (CPU_EPT | CPU_VPID)) != 0)
		ept_vpid.val = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	else
		ept_vpid.val = 0;
}

void init_vmx(u64 *vmxon_region)
{
	ulong fix_cr0_set, fix_cr0_clr;
	ulong fix_cr4_set, fix_cr4_clr;

	fix_cr0_set =  rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	fix_cr0_clr =  rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	fix_cr4_set =  rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	fix_cr4_clr = rdmsr(MSR_IA32_VMX_CR4_FIXED1);

	write_cr0((read_cr0() & fix_cr0_clr) | fix_cr0_set);
	write_cr4((read_cr4() & fix_cr4_clr) | fix_cr4_set | X86_CR4_VMXE);

	*vmxon_region = basic.revision;
}

static void alloc_bsp_vmx_pages(void)
{
	bsp_vmxon_region = alloc_page();
	guest_stack_top = (uintptr_t)alloc_page() + PAGE_SIZE;
	guest_syscall_stack_top = (uintptr_t)alloc_page() + PAGE_SIZE;
	vmcs_root = alloc_page();
}

static void init_bsp_vmx(void)
{
	init_vmx_caps();
	alloc_bsp_vmx_pages();
	init_vmx(bsp_vmxon_region);
}

static void init_vmcs_ctrl(void)
{
	/* 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA */
	/* 26.2.1.1 */
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	/* Disable VMEXIT of IO instruction */
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	if (ctrl_cpu_rev[0].set & CPU_SECONDARY) {
		ctrl_cpu[1] = (ctrl_cpu[1] | ctrl_cpu_rev[1].set) &
			ctrl_cpu_rev[1].clr;
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	}
	vmcs_write(CR3_TARGET_COUNT, 0);
	vmcs_write(VPID, ++vpid_cnt);
}

void enable_vmx(void)
{
	bool vmx_enabled =
		rdmsr(MSR_IA32_FEATURE_CONTROL) &
		FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if (!vmx_enabled) {
		wrmsr(MSR_IA32_FEATURE_CONTROL,
				FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX |
				FEATURE_CONTROL_LOCKED);
	}
}

static void init_vmcs_host(void)
{
	/* 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA */
	/* 26.2.1.2 */
	vmcs_write(HOST_EFER, rdmsr(MSR_EFER));

	/* 26.2.1.3 */
	vmcs_write(ENT_CONTROLS, ctrl_enter);
	vmcs_write(EXI_CONTROLS, ctrl_exit);

	/* 26.2.2 */
	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, read_cr3());
	vmcs_write(HOST_CR4, read_cr4());
	vmcs_write(HOST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(HOST_SYSENTER_CS,  KERNEL_CS);

	/* 26.2.3 */
	vmcs_write(HOST_SEL_CS, KERNEL_CS);
	vmcs_write(HOST_SEL_SS, KERNEL_DS);
	vmcs_write(HOST_SEL_DS, KERNEL_DS);
	vmcs_write(HOST_SEL_ES, KERNEL_DS);
	vmcs_write(HOST_SEL_FS, KERNEL_DS);
	vmcs_write(HOST_SEL_GS, KERNEL_DS);
	vmcs_write(HOST_SEL_TR, TSS_MAIN);
	vmcs_write(HOST_BASE_TR, get_gdt_entry_base(get_tss_descr()));
	vmcs_write(HOST_BASE_GDTR, gdt_descr.base);
	vmcs_write(HOST_BASE_IDTR, idt_descr.base);
	vmcs_write(HOST_BASE_FS, 0);
	vmcs_write(HOST_BASE_GS, rdmsr(MSR_GS_BASE));

	/* Set other vmcs area */
	vmcs_write(PF_ERROR_MASK, 0);
	vmcs_write(PF_ERROR_MATCH, 0);
	vmcs_write(VMCS_LINK_PTR, ~0ul);
	vmcs_write(VMCS_LINK_PTR_HI, ~0ul);
	vmcs_write(HOST_RIP, (u64)(&vmx_return));
}

static void init_vmcs_guest(void)
{
	gdt_entry_t *tss_descr = get_tss_descr();

	/* 26.3 CHECKING AND LOADING GUEST STATE */
	ulong guest_cr0, guest_cr4, guest_cr3;
	/* 26.3.1.1 */
	guest_cr0 = read_cr0();
	guest_cr4 = read_cr4();
	guest_cr3 = read_cr3();
	if (ctrl_enter & ENT_GUEST_64) {
		guest_cr0 |= X86_CR0_PG;
		guest_cr4 |= X86_CR4_PAE;
	}
	if ((ctrl_enter & ENT_GUEST_64) == 0)
		guest_cr4 &= (~X86_CR4_PCIDE);
	if (guest_cr0 & X86_CR0_PG)
		guest_cr0 |= X86_CR0_PE;
	vmcs_write(GUEST_CR0, guest_cr0);
	vmcs_write(GUEST_CR3, guest_cr3);
	vmcs_write(GUEST_CR4, guest_cr4);
	vmcs_write(GUEST_SYSENTER_CS,  KERNEL_CS);
	vmcs_write(GUEST_SYSENTER_ESP, guest_syscall_stack_top);
	vmcs_write(GUEST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(GUEST_DR7, 0);
	vmcs_write(GUEST_EFER, rdmsr(MSR_EFER));

	/* 26.3.1.2 */
	vmcs_write(GUEST_SEL_CS, KERNEL_CS);
	vmcs_write(GUEST_SEL_SS, KERNEL_DS);
	vmcs_write(GUEST_SEL_DS, KERNEL_DS);
	vmcs_write(GUEST_SEL_ES, KERNEL_DS);
	vmcs_write(GUEST_SEL_FS, KERNEL_DS);
	vmcs_write(GUEST_SEL_GS, KERNEL_DS);
	vmcs_write(GUEST_SEL_TR, TSS_MAIN);
	vmcs_write(GUEST_SEL_LDTR, 0);

	vmcs_write(GUEST_BASE_CS, 0);
	vmcs_write(GUEST_BASE_ES, 0);
	vmcs_write(GUEST_BASE_SS, 0);
	vmcs_write(GUEST_BASE_DS, 0);
	vmcs_write(GUEST_BASE_FS, 0);
	vmcs_write(GUEST_BASE_GS, rdmsr(MSR_GS_BASE));
	vmcs_write(GUEST_BASE_TR, get_gdt_entry_base(tss_descr));
	vmcs_write(GUEST_BASE_LDTR, 0);

	vmcs_write(GUEST_LIMIT_CS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_DS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_ES, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_SS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_FS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_GS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_LDTR, 0xffff);
	vmcs_write(GUEST_LIMIT_TR, get_gdt_entry_limit(tss_descr));

	vmcs_write(GUEST_AR_CS, 0xa09b);
	vmcs_write(GUEST_AR_DS, 0xc093);
	vmcs_write(GUEST_AR_ES, 0xc093);
	vmcs_write(GUEST_AR_FS, 0xc093);
	vmcs_write(GUEST_AR_GS, 0xc093);
	vmcs_write(GUEST_AR_SS, 0xc093);
	vmcs_write(GUEST_AR_LDTR, 0x82);
	vmcs_write(GUEST_AR_TR, 0x8b);

	/* 26.3.1.3 */
	vmcs_write(GUEST_BASE_GDTR, gdt_descr.base);
	vmcs_write(GUEST_BASE_IDTR, idt_descr.base);
	vmcs_write(GUEST_LIMIT_GDTR, gdt_descr.limit);
	vmcs_write(GUEST_LIMIT_IDTR, idt_descr.limit);

	/* 26.3.1.4 */
	vmcs_write(GUEST_RIP, (u64)(&guest_entry));
	vmcs_write(GUEST_RSP, guest_stack_top);
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED);

	/* 26.3.1.5 */
	vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
	vmcs_write(GUEST_INTR_STATE, 0);
}

int init_vmcs(struct vmcs **vmcs)
{
	*vmcs = alloc_page();
	(*vmcs)->hdr.revision_id = basic.revision;
	/* vmclear first to init vmcs */
	if (vmcs_clear(*vmcs)) {
		printf("%s : vmcs_clear error\n", __func__);
		return 1;
	}

	if (make_vmcs_current(*vmcs)) {
		printf("%s : make_vmcs_current error\n", __func__);
		return 1;
	}

	/* All settings to pin/exit/enter/cpu
	   control fields should be placed here */
	ctrl_pin |= PIN_EXTINT | PIN_NMI | PIN_VIRT_NMI;
	ctrl_exit = EXI_LOAD_EFER | EXI_HOST_64;
	ctrl_enter = (ENT_LOAD_EFER | ENT_GUEST_64);
	/* DIsable IO instruction VMEXIT now */
	ctrl_cpu[0] &= (~(CPU_IO | CPU_IO_BITMAP));
	ctrl_cpu[1] = 0;

	ctrl_pin = (ctrl_pin | ctrl_pin_rev.set) & ctrl_pin_rev.clr;
	ctrl_enter = (ctrl_enter | ctrl_enter_rev.set) & ctrl_enter_rev.clr;
	ctrl_exit = (ctrl_exit | ctrl_exit_rev.set) & ctrl_exit_rev.clr;
	ctrl_cpu[0] = (ctrl_cpu[0] | ctrl_cpu_rev[0].set) & ctrl_cpu_rev[0].clr;

	init_vmcs_ctrl();
	init_vmcs_host();
	init_vmcs_guest();
	return 0;
}

static void __attribute__((__used__)) guest_main(void)
{
	printf("Hello from guest!\n");
	asm("mov %cr3,%rax\n\t");
}

/* guest_entry */
asm(
	".align	4, 0x90\n\t"
	".globl	entry_guest\n\t"
	"guest_entry:\n\t"
	"	call guest_main\n\t"
	"	vmcall\n\t"
);

static noinline void vmx_enter_guest(struct vmentry_result *result)
{
	memset(result, 0, sizeof(*result));

	asm volatile (
		"mov %[HOST_RSP], %%rdi\n\t"
		"vmwrite %%rsp, %%rdi\n\t"
		"cmpb $0, %[launched]\n\t"
		"jne 1f\n\t"
		"vmlaunch\n\t"
		"jmp 2f\n\t"
		"1: "
		"vmresume\n\t"
		"2: "
		"pushf\n\t"
		"pop %%rdi\n\t"
		"mov %%rdi, %[vm_fail_flags]\n\t"
		"movl $1, %[vm_fail]\n\t"
		"jmp 3f\n\t"
		"vmx_return:\n\t"
		"3: \n\t"
		: [vm_fail]"+m"(result->vm_fail),
		  [vm_fail_flags]"=m"(result->flags)
		: [launched]"m"(launched), [HOST_RSP]"i"(HOST_RSP)
		: "rdi", "memory", "cc"
	);

	result->vmlaunch = !launched;
	result->instr = launched ? "vmresume" : "vmlaunch";
	result->exit_reason.full = result->vm_fail ? 0xdead :
						     vmcs_read(EXI_REASON);
	result->entered = !result->vm_fail &&
			  !result->exit_reason.failed_vmentry;
}

int main(int argc, const char *argv[])
{
	struct vmcs *vmcs;
	struct vmentry_result result;
	u64 val, guest_rip, insn_len;

	setup_vm();
	init_bsp_vmx();
	if (!this_cpu_has(X86_FEATURE_VMX)) {
		printf("WARNING: vmx not supported, add '-cpu host'\n");
		return 1;
	}
	enable_vmx();

	printf("VMXON\n");
	vmx_on();

	init_vmcs(&vmcs);

	val = vmcs_read(CPU_EXEC_CTRL0);
	vmcs_write(CPU_EXEC_CTRL0, val | CPU_CR3_STORE);

	vmx_enter_guest(&result);

	if (result.entered)
		launched = true;

	if (result.exit_reason.full == VMX_CR) {
		printf("VM exit due to CR3 load/store\n");

		insn_len = vmcs_read(EXI_INST_LEN);
		guest_rip = vmcs_read(GUEST_RIP);
		vmcs_write(GUEST_RIP, guest_rip + insn_len);

		printf("Resuming guest\n");
		vmx_enter_guest(&result);
		if (result.exit_reason.full == VMX_VMCALL)
			printf("VM exit due to VMCALL\n");
	} else if (result.exit_reason.full == VMX_VMCALL) {
		printf("VM exit due to VMCALL\n");
	} else {
		printf("VM entry failed? %u\n", result.vm_fail);
		printf("Unexpected VM exit reason: %u\n", result.exit_reason.full);
	}

	vmx_off();
	printf("VMXOFF\n");

	free_page(vmcs);

	return 0;
}
