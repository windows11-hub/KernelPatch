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
#include <linux/moduleparam.h>

/* Staged bring-up.
 *
 * Every earlier attempt ended the same way: the kernel panicked inside a hook
 * before it could log anything, so the watchdog reset and the only evidence was
 * "it rebooted". A module parameter turns that single all-or-nothing load into
 * a sequence of steps that can be bisected from outside:
 *
 *   0  patch memory only                     (one init_mm lookup)
 *   1  + accctl symbol resolve
 *   2  + hook runtime init                   (7 lookups, then an alloc probe)
 *   3  + one trivial inline hook             (proves the hook engine works)
 *   4  + CFI bypass + manager scan
 *   5  + selinux_hook                        (full module)
 *
 * Load with: insmod kernelpatch.ko kp_stage=N
 * Each stage logs a marker before and after, so the last line in dmesg names
 * the step that died. */
static int kp_stage = 5;
module_param(kp_stage, int, 0644);
MODULE_PARM_DESC(kp_stage, "Bring-up stage 0-5 (default 5, full module)");

#include "../include/kp_lkm.h"
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"
#include <hook.h>
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



/* ---- stage 2: hook engine smoke test ----------------------------------
 *
 * Hooks a kernel function that is effectively never called at runtime, so the
 * trampoline is installed and the text is patched, but nothing executes the
 * hook. That separates two failure modes that both end in a watchdog reset:
 *
 *   - install-time fault: the panic happens during insmod, the marker after
 *     this function never prints, and the log stops right here.
 *   - execution-time fault: install succeeds and the reset only happens once
 *     something actually calls the hooked function.
 *
 * kp_report_unused is a no-op symbol lookup target; if the kernel lacks it the
 * test picks the next candidate. The callback does nothing at all.
 */
static void kp_smoke_before(hook_fargs0_t *a, void *u)
{
    (void)a;
    (void)u;
}

int kp_hook_smoke_test(void)
{
    static const char *const candidates[] = {
        "panic_on_oops_show",
        "reset_devices_show",
        "sysctl_overload_detect_stack_show",
        "printk_ratelimit_state",
    };
    void *target = NULL;
    const char *name = NULL;
    hook_err_t err;
    unsigned int i;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        target = kp_resolve_symbol_variant(candidates[i]);
        if (target) {
            name = candidates[i];
            break;
        }
    }

    if (!target) {
        logkw("stage 2: no smoke-test target found, skipping\n");
        return 0;
    }

    logki("stage 2: hooking %s at %px\n", name, target);
    err = hook_wrap(target, 0, (void *)kp_smoke_before, NULL, NULL);
    logki("stage 2: hook_wrap returned %d\n", err);
    if (err)
        return (int)err;

    logki("stage 2: hook installed, target never called by the test\n");
    return 0;
}

int __init kernelpatch_init(void)
{
	int rc;

	logki("KernelPatch LKM loading (version %x, kernel %x, stage %d)\n",
	      kpver, (unsigned)LINUX_VERSION_CODE, kp_stage);

	logki("stage 0: symbol resolver\n");
	kp_symres_init();

	logki("stage 0: patch memory\n");
	rc = kp_patch_memory_init();
	if (rc) {
		logke("stage 0 failed: patch memory %d\n", rc);
		return rc;
	}
	logki("stage 0 done (patch memory only)\n");

	if (kp_stage < 1) {
		logki("KernelPatch LKM stopped at stage 0\n");
		return 0;
	}

	logki("stage 1: accctl symbol resolve\n");
	rc = kp_accctl_init();
	if (rc) {
		logke("stage 1 failed: accctl %d\n", rc);
		return rc;
	}
	logki("stage 1: accctl done\n");

	if (kp_stage < 5) {
		logki("KernelPatch LKM stopped at stage 4\n");
		return 0;
	}

	logki("stage 2: hook runtime\n");
	rc = kp_hook_runtime_init();
	if (rc) {
		logke("stage 2 failed: hook runtime %d\n", rc);
		return rc;
	}
	logki("stage 4 done\n");

	if (kp_stage < 2) {
		logki("KernelPatch LKM stopped at stage 1\n");
		return 0;
	}

	logki("stage 3: smoke hook\n");
	rc = kp_hook_smoke_test();
	if (rc) {
		logke("stage 3 failed: smoke hook %d\n", rc);
		return rc;
	}
	logki("stage 2 done\n");

	if (kp_stage < 3) {
		logki("KernelPatch LKM stopped at stage 2\n");
		return 0;
	}

	logki("stage 4: CFI bypass\n");
	rc = kp_bypass_kcfi();
	if (rc)
		logkw("stage 4: CFI bypass failed: %d (continuing)\n", rc);

	logki("stage 4: manager scan\n");
	kp_manager_init();
	logki("stage 3 done\n");

	if (kp_stage < 4) {
		logki("KernelPatch LKM stopped at stage 3\n");
		return 0;
	}

	logki("stage 5: selinux_hook\n");
	rc = (int)selinux_hook_init(NULL, "lkm", NULL);
	if (rc)
		logkw("stage 5: selinux_hook init failed: %d\n", rc);

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
