// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch LKM entry, "pure KernelPatch" shape.
 *
 * What this module is now:
 *   - the inline hook engine and its trampoline runtime (hook/)
 *   - symbol resolution and kernel text/memory patching (infra/)
 *   - credential switching (supercall/accctl.c: kp_commit_su / kp_task_su)
 *   - selinux_hook, linked in rather than loaded as a .kpm
 *
 * What was removed and why:
 *   - kpm/  the KPM loader. selinux_hook used to be a .kpm; it is a normal
 *     object in this module now, so nothing needs a runtime loader.
 *   - supercall/  the syscall-45 channel plus dispatch, su and kstorage. With
 *     it goes every syscall-table hook this module used to install.
 *   - supercall/sucompat*  the execve redirect.
 *   - infra/syscall_table.c  only the two items above used it.
 *
 * Consequence, stated plainly: there is no syscall hook left, and no supercall
 * channel for a manager app to talk to. This module only does inline hooks.
 */
#include <linux/module.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"
#include "../hook/hook_runtime.h"
#include "../manager/manager.h"
#include "../supercall/accctl.h"
#include "../infra/secpass.h"

/* selinux_hook was Admirepowered/selinux_hook, distributed as a .kpm. It now
 * compiles into kernelpatch.ko: the KPM header macros became plain constants
 * and the KPM_INIT/KPM_CTL0/KPM_EXIT entry points became these functions.
 *
 * It answers selinuxfs queries (/sys/fs/selinux/access, /context, the procattr
 * writes, the status reads) with the clean-policy result, so a caller probing
 * for Magisk types gets EINVAL exactly as it would on an unmodified device.
 * That is what kp_selinux_bypass_init() in accctl.c used to fake from the
 * opposite direction; running both would make compute_av and avc_has_perm
 * disagree, so the bypass was deleted when this was linked in. */
extern long selinux_hook_init(const char *args, const char *event, void *__user r);
extern long selinux_hook_exit(void *__user r);

/*
 * Some A12-5.10 third-party kernels advertise CC_HAVE_STACKPROTECTOR_SYSREG but
 * don't provide __stack_chk_guard for modules; the DDK toolchain then generates
 * references to it. Manually provide it (same workaround as KernelSU).
 */
#if defined(CONFIG_STACKPROTECTOR) && defined(CONFIG_ARM64) && defined(MODULE) && \
    !defined(CONFIG_STACKPROTECTOR_PER_TASK)
#include <linux/random.h>
#include <linux/stackprotector.h>

unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init setup_stack_chk_guard(void)
{
	unsigned long canary;
	get_random_bytes(&canary, sizeof(canary));
	canary ^= LINUX_VERSION_CODE;
	canary &= CANARY_MASK;
	__stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelpatch_init_early(void)
{
	asm("mov x19, x30;"
	    "bl setup_stack_chk_guard;"
	    "mov x30, x19;"
	    "b kernelpatch_init;");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

int __init kernelpatch_init(void)
{
	int rc;

	logki("KernelPatch LKM loading (version %x, kernel %x)\n", kpver, (unsigned)LINUX_VERSION_CODE);

	kp_symres_init();

	rc = kp_patch_memory_init();
	if (rc)
		return rc;

	rc = kp_accctl_init();
	if (rc)
		return rc;

	rc = kp_hook_runtime_init();
	if (rc)
		/* No executable-memory path for hook trampolines (set_memory_x and
		 * execmem_alloc both missing). Continuing would call a NULL allocator
		 * and crash the kernel; fail the load cleanly instead. */
		return rc;

	rc = kp_bypass_kcfi();
	if (rc)
		logkw("CFI bypass failed: %d\n", rc);

	/* Scan for the trusted manager. Runs in the caller's (root) context so
	 * SELinux allows reading /data. Nothing in this module depends on the
	 * result any more - it is kept because accctl/apk_sign support it and a
	 * future caller may want kp_is_manager_uid() - so a miss is not fatal. */
	kp_manager_init();

	/* Filter the selinuxfs query surface. Must run after kp_hook_runtime_init()
	 * (it needs the trampoline allocator) and last of all, because it snapshots
	 * the live policy and that policy must be fully committed by now. */
	rc = (int)selinux_hook_init(NULL, "lkm", NULL);
	if (rc)
		logkw("selinux_hook init failed: %d\n", rc);

	logki("KernelPatch LKM ready\n");
	return 0;
}

static void __exit kernelpatch_exit(void)
{
	selinux_hook_exit(NULL);
	/* Unhook the CFI bypass last so it shields the teardown above from
	 * spurious CFI failures on LKM text. */
	kp_bypass_kcfi_exit();
	logki("KernelPatch LKM unloaded\n");
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelpatch_init_early);
#else
module_init(kernelpatch_init);
#endif
module_exit(kernelpatch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelPatch LKM");
MODULE_VERSION(KP_LKM_VERSION_STRING);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
