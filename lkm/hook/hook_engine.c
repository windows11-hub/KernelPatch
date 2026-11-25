// SPDX-License-Identifier: GPL-2.0-or-later
/* Reuse KernelPatch's ARM64 relocation and hook-chain engine. */
#include <linux/compiler.h>
#include <linux/types.h>

#ifndef __noinline
#define __noinline noinline
#endif

/*
 * KCFI exemption for the transit stubs in kernel/base/hook.c.
 *
 * Original KP links those four functions into hand-written .transitN.text
 * sections and copies the bytes into hook memory, so no compiler ever
 * instrumented them. The LKM build has no such linker markers: the trampoline
 * jumps to the resident C functions instead (see hook_chain_prepare below),
 * which means they ARE instrumented - and they make indirect calls to
 * relocated instruction bytes and to arbitrary hook callbacks, none of which
 * carry a CFI type hash.
 *
 * The consequence was measured, not theorised. getname_flags hooked, first
 * openat() after load:
 *   cfi_handler -> brk_handler -> do_debug_exception   (ESR 0xf2008228, KCFI)
 *   __replace_report_cfi_failure [kernelpatch]          (secpass.c hook)
 *   _transit4 -> getname -> do_sys_openat2
 * report_cfi_failure is itself hooked for the CFI-bypass feature, so the
 * failure re-entered the same stub until the kernel stack overflowed and the
 * board hard-rebooted 70 seconds after insmod.
 *
 * no_sanitize("cfi") suppresses the type-hash load at each indirect call in
 * these four functions. It has to be set here rather than in hook.c so the GKI
 * build of that file stays byte-identical to upstream.
 */
/* no_sanitize names must match what the kernel actually enables: -fsanitize=kcfi.
 * The string "cfi" refers to the legacy sanitizer and is accepted by the
 * compiler but matches nothing when kcfi is on, so both spellings are listed. */
#define KP_TRANSIT_ATTR __attribute__((no_sanitize("cfi", "kcfi")))

/* The original kpimg linker script provides _transit*_end and copies each
 * transit function into hook memory. Linux modules have no such linker
 * markers, so emit a small absolute branch to the resident LKM function. */
#define KP_HOOK_EXTERNAL_CHAIN_PREPARE

#include "../../kernel/base/hook.c"

static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
	uint64_t target;
	hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);

	if (argno < 0 || argno > 12)
		return -HOOK_BAD_ADDRESS;
	if (argno == 0)
		target = (uint64_t)_transit0;
	else if (argno <= 4)
		target = (uint64_t)_transit4;
	else if (argno <= 8)
		target = (uint64_t)_transit8;
	else
		target = (uint64_t)_transit12;

	transit[0] = ARM64_BTI_JC;
	transit[1] = 0x58000070; /* LDR X16, #12 */
	transit[2] = 0x14000004; /* B #16 */
	transit[3] = ARM64_NOP;
	transit[4] = (uint64_t)chain;
	transit[5] = (uint64_t)chain >> 32;
	return branch_absolute(&transit[6], target) ? HOOK_NO_ERR : -HOOK_TRANSIT_NO_MEM;
}
