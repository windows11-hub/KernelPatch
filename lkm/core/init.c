// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch LKM entry.
 *
 * What this module is:
 *   - the inline hook engine and its trampoline runtime (hook/)
 *   - symbol resolution and kernel text/memory patching (infra/)
 *   - credential switching (supercall/accctl.c)
 *   - selinux_hook, linked in rather than loaded as a .kpm
 *
 * Removed on purpose: kpm/ (the KPM loader), supercall/ (the syscall-45 channel,
 * dispatch, su, kstorage), supercall/sucompat* (the execve redirect) and
 * infra/syscall_table.c. Nothing here installs a syscall hook any more.
 *
 * ---- staged bring-up --------------------------------------------------
 *
 * Every earlier attempt ended the same way: the kernel died inside a hook
 * before it could log anything, the watchdog reset the machine, and the only
 * evidence was "it rebooted". kp_stage turns one all-or-nothing load into a
 * sequence that can be bisected from outside; the last line in dmesg names the
 * step that failed.
 *
 *   0  patch memory only        (one symbol lookup, no hook, no exec pages)
 *   1  + accctl                 (selinux_blob_sizes, validated before use)
 *   2  + hook runtime           (7 lookups, then an allocator probe)
 *   3  + one trivial inline hook
 *   4  + CFI bypass + manager scan
 *   5  + selinux_hook           (full module, the default)
 *
 * Each gate is a single "if (kp_stage < N) return 0;" immediately after the
 * work for stage N-1. The gates are deliberately NOT renumbered or reordered
 * anywhere else: a previous revision had them out of order, so kp_stage=1 ran
 * the hook runtime anyway and the bisect was meaningless.
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/moduleparam.h>

#include "../include/kp_lkm.h"
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"
#include "../hook/hook_runtime.h"
#include "../manager/manager.h"
#include "../supercall/accctl.h"
#include "../infra/secpass.h"
#include <hook.h>

/* There is deliberately NO module parameter here.
 *
 * module_param(x, int, ...) expands to a reference to param_ops_int, which is
 * declared in <linux/moduleparam.h> but not exported by this kernel
 * (kernel/params.c has no EXPORT_SYMBOL for it). Naming it at all leaves an
 * undefined symbol and insmod refuses the module.
 *
 * Staged bring-up is therefore compile-time: KP_BRINGUP_STAGE is set through
 * ccflags in the Kbuild, so a diagnostic build is a rebuild rather than a
 * parameter. For normal use it stays at the last stage, i.e. full module. */
#ifndef KP_BRINGUP_STAGE
#define KP_BRINGUP_STAGE 5
#endif
#define kp_stage KP_BRINGUP_STAGE

/* selinux_hook was Admirepowered/selinux_hook, distributed as a .kpm. It now
 * compiles into kernelpatch.ko: the KPM header macros became plain constants
 * and the KPM_INIT/KPM_CTL0/KPM_EXIT entry points became these functions.
 *
 * It answers selinuxfs queries (/sys/fs/selinux/access, /context, the procattr
 * writes, the status reads) with the clean-policy result, so a caller probing
 * for Magisk types gets EINVAL exactly as it would on an unmodified device. */
extern long selinux_hook_init(const char *args, const char *event, void *__user r);
extern long selinux_hook_exit(void *__user r);

extern int kp_hook_smoke_test(void);

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

/* Every stage logs before and after its work, so a crash leaves the "before"
 * line as the last thing in the buffer and names the failing step. */
#define KP_STAGE_ENTER(n, what) logki("stage %d: %s\n", (n), (what))
#define KP_STAGE_DONE(n)        logki("stage %d: done\n", (n))
#define KP_STAGE_STOP(n)                                                   \
	do {                                                               \
		logki("KernelPatch LKM stopped after stage %d (kp_stage=%d)\n", \
		      (n), kp_stage);                                      \
		return 0;                                                  \
	} while (0)

int __init kernelpatch_init(void)
{
	int rc;

	logki("KernelPatch LKM loading (version %x, kernel %x, stage %d)\n",
	      kpver, (unsigned)LINUX_VERSION_CODE, kp_stage);

	/* ---- stage 0 ---------------------------------------------------- */
	KP_STAGE_ENTER(0, "symbol resolver");
	kp_symres_init();
	KP_STAGE_ENTER(0, "patch memory");
	rc = kp_patch_memory_init();
	if (rc) {
		logke("stage 0 failed: patch memory %d\n", rc);
		return rc;
	}
	KP_STAGE_DONE(0);
	if (kp_stage < 1)
		KP_STAGE_STOP(0);

	/* ---- stage 1 ---------------------------------------------------- */
	KP_STAGE_ENTER(1, "accctl (selinux_blob_sizes)");
	rc = kp_accctl_init();
	if (rc) {
		logke("stage 1 failed: accctl %d\n", rc);
		return rc;
	}
	KP_STAGE_DONE(1);
	if (kp_stage < 2)
		KP_STAGE_STOP(1);

	/* ---- stage 2 ---------------------------------------------------- */
	KP_STAGE_ENTER(2, "hook runtime");
	rc = kp_hook_runtime_init();
	if (rc) {
		logke("stage 2 failed: hook runtime %d\n", rc);
		return rc;
	}
	KP_STAGE_DONE(2);
	if (kp_stage < 3)
		KP_STAGE_STOP(2);

	/* ---- stage 3 ---------------------------------------------------- */
	KP_STAGE_ENTER(3, "smoke hook");
	rc = kp_hook_smoke_test();
	if (rc) {
		logke("stage 3 failed: smoke hook %d\n", rc);
		return rc;
	}
	KP_STAGE_DONE(3);
	if (kp_stage < 4)
		KP_STAGE_STOP(3);

	/* ---- stage 4 ---------------------------------------------------- */
	KP_STAGE_ENTER(4, "CFI bypass");
	rc = kp_bypass_kcfi();
	if (rc)
		logkw("stage 4: CFI bypass failed: %d (continuing)\n", rc);

	KP_STAGE_ENTER(4, "manager scan");
	kp_manager_init();
	KP_STAGE_DONE(4);
	if (kp_stage < 5)
		KP_STAGE_STOP(4);

	/* ---- stage 5 ---------------------------------------------------- */
	KP_STAGE_ENTER(5, "selinux_hook");
	rc = (int)selinux_hook_init(NULL, "lkm", NULL);
	if (rc)
		logkw("stage 5: selinux_hook init failed: %d\n", rc);
	KP_STAGE_DONE(5);

	logki("KernelPatch LKM ready\n");
	return 0;
}

static void __exit kernelpatch_exit(void)
{
	if (kp_stage >= 5)
		selinux_hook_exit(NULL);
	/* Unhook the CFI bypass last so it shields the teardown above from
	 * spurious CFI failures on LKM text. */
	if (kp_stage >= 4)
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
/* Namespaces actually used by this module.
 *
 * Verified against oppo-source/android_kernel_oppo_sm8750: the symbols below
 * are exported with EXPORT_SYMBOL_NS(..., <ns>) rather than EXPORT_SYMBOL, and
 * a module that references them without importing the namespace is rejected
 * by the loader.
 *
 *   ANDROID_GKI_VFS_EXPORT_ONLY
 *     filp_open, kernel_read, prepare_creds   <- all three used in this tree
 *     (also dentry_open, generic_file_open, kernel_write,
 *      iter_file_splice_write, fiemap_*, override_creds, revert_creds)
 *
 *   VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver
 *     the classic VFS internals namespace, kept because manager/apk_sign.c and
 *     infra/patch_memory.c reach VFS entry points that still live there.
 *
 * MODULE_IMPORT_NS is variadic-only from 6.13; older trees take a bare token,
 * so the two spellings are kept apart as before.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
MODULE_IMPORT_NS("ANDROID_GKI_VFS_EXPORT_ONLY");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_IMPORT_NS(ANDROID_GKI_VFS_EXPORT_ONLY);
#endif
