// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Stage-3 hook engine smoke test.
 *
 * Hooks a kernel function that is effectively never called at runtime, so the
 * trampoline is installed and the text is patched but nothing executes the
 * hook. That separates two failure modes that both end in a watchdog reset:
 *
 *   - install-time fault: the panic happens during insmod and the marker after
 *     this function never prints, so the log stops right here.
 *   - execution-time fault: install succeeds and the reset only happens once
 *     something actually calls the hooked function.
 *
 * The callback does nothing at all. If no candidate resolves, the test is
 * skipped and the module continues - a missing smoke target is not a failure.
 */
#include <linux/kernel.h>
#include <linux/types.h>

#include <hook.h>

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"

static void kp_smoke_before(hook_fargs0_t *a, void *u)
{
	(void)a;
	(void)u;
}

int kp_hook_smoke_test(void)
{
	/* Read-only sysfs attribute show() functions: reachable, but only when
	 * someone reads the corresponding /sys file, which nothing does during
	 * boot. Any of them proves the trampoline path works. */
	static const char *const candidates[] = {
		"panic_on_oops_show",
		"reset_devices_show",
		"panic_on_warn_show",
		"panic_timeout_show",
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
		logkw("stage 3: no smoke-test target resolved, skipping\n");
		return 0;
	}

	logki("stage 3: hooking %s at %px\n", name, target);
	err = hook_wrap(target, 0, (void *)kp_smoke_before, NULL, NULL);
	logki("stage 3: hook_wrap(%s) returned %d\n", name, (int)err);
	if (err) {
		logke("stage 3: hook_wrap failed, engine unusable\n");
		return (int)err;
	}

	logki("stage 3: hook installed, target not called by the test\n");
	return 0;
}
