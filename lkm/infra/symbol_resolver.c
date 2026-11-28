// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver for the LKM.
 *
 * The old implementation was a one-liner over kallsyms_lookup_name(). That is
 * wrong on this platform: the symbol is linked (so the call compiles and the
 * module loads), but on this vendor kernel it returns 0 for every name. The
 * result was silent: module_alloc, set_memory_x, init_mm and selinux_blob_sizes
 * all came back NULL, every feature disabled itself, and nothing said why.
 *
 * kallsyms_on_each_symbol() is also exported here and does work, so use it as
 * the primary path: walk the table once, cache the names we care about, and
 * fall back to kallsyms_lookup_name only if the walk is unavailable.
 *
 * The signature of kallsyms_on_each_symbol changed at 6.4 in both the callback
 * and the call:
 *
 *   < 6.4   int f(int (*cb)(void *, const char *, unsigned long), void *data)
 *   >= 6.4  int f(int (*cb)(void *, const char *, struct module *,
 *                           unsigned long), void *data, struct module *mod)
 *
 * and some vendor 5.10/5.15 trees backported the module argument, so the shape
 * is chosen at runtime from kver rather than at compile time.
 */
#include "symbol_resolver.h"

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"

/* kver and VERSION() live in infra/kp_globals.c. */
extern uint32_t kver;
#ifndef VERSION
#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))
#endif

#define KP_SYM_CACHE_MAX 32

struct kp_sym_entry {
	const char *name;
	unsigned long addr;
};

static struct kp_sym_entry kp_sym_cache[KP_SYM_CACHE_MAX];
static int kp_sym_cache_count;
static bool kp_sym_cache_ready;

/* The walk function, taken by name so no prototype has to match. */
static unsigned long kp_each_addr;

/* ---- table walk ------------------------------------------------------- */

struct kp_walk_ctx {
	const char *want;
	unsigned long addr;
};

static int kp_walk_match(void *data, const char *name, unsigned long addr)
{
	struct kp_walk_ctx *ctx = data;

	if (!name || !addr)
		return 0;
	if (!strcmp(name, ctx->want)) {
		ctx->addr = addr;
		return 1;	/* stop at the exact match */
	}
	return 0;
}

typedef int (*kp_walk_cb3_t)(void *, const char *, unsigned long);
typedef int (*kp_walk_cb4_t)(void *, const char *, struct module *, unsigned long);
typedef int (*kp_each_3_t)(kp_walk_cb3_t, void *);
typedef int (*kp_each_4_t)(kp_walk_cb4_t, void *, struct module *);

static int kp_walk_cb3(void *data, const char *name, unsigned long addr)
{
	return kp_walk_match(data, name, addr);
}

static int kp_walk_cb4(void *data, const char *name, struct module *m, unsigned long addr)
{
	(void)m;
	return kp_walk_match(data, name, addr);
}

/* One walk, one symbol. The cache below turns repeated lookups into a linear
 * scan of a small array instead of another pass over kallsyms. */
static unsigned long kp_walk_lookup(const char *name)
{
	struct kp_walk_ctx ctx = { .want = name, .addr = 0 };

	if (!kp_each_addr)
		return 0;

	if (kver >= VERSION(6, 4, 0))
		(void)((kp_each_4_t)kp_each_addr)(kp_walk_cb4, &ctx, NULL);
	else
		(void)((kp_each_3_t)kp_each_addr)(kp_walk_cb3, &ctx);

	return ctx.addr;
}

/* ---- public API ------------------------------------------------------- */

unsigned long kp_resolve_symbol(const char *name)
{
	unsigned long addr;
	int i;

	if (!name)
		return 0;

	/* Cache first: hook init asks for the same handful of names repeatedly. */
	if (kp_sym_cache_ready) {
		for (i = 0; i < kp_sym_cache_count; i++) {
			if (!strcmp(kp_sym_cache[i].name, name))
				return kp_sym_cache[i].addr;
		}
	}

	/* Primary: walk the kallsyms table. This is the path that actually works
	 * on this kernel. */
	addr = kp_walk_lookup(name);

	/* Fallback only. On this platform it returns 0 for everything, so it is
	 * kept purely so a kernel where the walk is unavailable still has a
	 * chance, and the log below makes the outcome explicit either way. */
	if (!addr)
		addr = kallsyms_lookup_name(name);

	if (kp_sym_cache_ready && kp_sym_cache_count < KP_SYM_CACHE_MAX) {
		kp_sym_cache[kp_sym_cache_count].name = name;
		kp_sym_cache[kp_sym_cache_count].addr = addr;
		kp_sym_cache_count++;
	}

	return addr;
}

void *kp_resolve_symbol_variant(const char *name)
{
	char cfi_name[KSYM_NAME_LEN];
	unsigned long jt;
	unsigned long exact;
	int n;

	if (!name)
		return NULL;

	/* Traditional CFI (< 6.1) requires calling functions through their .cfi_jt
	 * canonical-jump-table entry, not the function body - a direct indirect
	 * call to the body trips __cfi_check (panic). */
	n = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", name);
	if (n > 0 && n < (int)sizeof(cfi_name)) {
		jt = kp_walk_lookup(cfi_name);
		if (!jt)
			jt = kallsyms_lookup_name(cfi_name);
		if (jt)
			return (void *)jt;
	}

	exact = kp_resolve_symbol(name);
	return (void *)exact;
}

void kp_symres_init(void)
{
	kp_sym_cache_count = 0;
	kp_sym_cache_ready = true;

	/* Take the walk function's address by name through the assembler: the
	 * symbol is linked, so &fn is a compile-time constant and a NULL test on
	 * it is always false (the kernel build rejects that under -Werror), and
	 * its prototype differs per kernel so no single cast fits. adrp/add gives
	 * a plain integer with no function type involved. */
	asm volatile("adrp %0, kallsyms_on_each_symbol\n\t"
		     "add  %0, %0, :lo12:kallsyms_on_each_symbol"
		     : "=r"(kp_each_addr));

	logki("symbol resolver: on_each_symbol=%px lookup_name=%px\n",
	      (void *)kp_each_addr, (void *)kallsyms_lookup_name);

	if (!kp_each_addr)
		logkw("symbol resolver: table walk unavailable, falling back to kallsyms_lookup_name only\n");
}
