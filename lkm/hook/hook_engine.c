// SPDX-License-Identifier: GPL-2.0-or-later
/* Reuse KernelPatch's ARM64 relocation and hook-chain engine. */
#include <linux/compiler.h>
#include <linux/types.h>

#ifndef __noinline
#define __noinline noinline
#endif

/*
 * The transit stubs no longer need a CFI exemption.
 *
 * They used to call hook_chain->hook.relo_addr and the chain callbacks as C
 * function pointers, which made the compiler emit a KCFI type-hash check that
 * cannot pass for relocated instruction bytes (no hash in front of them) - so
 * every such call panicked with "Oops - CFI". The exemption was attempted
 * three ways (no_sanitize("cfi"), no_sanitize("kcfi"), -fno-sanitize=kcfi) and
 * each had a failure mode: wrong sanitizer name, unsupported name on clang 12,
 * or a module-wide blanket that left any forgotten object exposed.
 *
 * kernel/base/hook.c now routes those calls through kp_call.h, which issues
 * them with inline asm (blr) so no check is generated at all. CFI stays on for
 * the whole module and this file needs no special flags.
 */

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
