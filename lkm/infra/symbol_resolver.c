// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver. On GKI kernels kallsyms_lookup_name is exported to
 * modules (the mainline 5.7 de-export was reversed for Android vendor use), so
 * we link it directly and bootstrap everything else by name. kallsyms_on_each_
 * symbol is NOT exported on 5.10; resolve it by name into a function pointer
 * for CFI/llvm-mangled variant matching.
 */
#include "symbol_resolver.h"

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"
#include "../include/kp_call.h"

/* kallsyms_on_each_symbol() changed in BOTH directions at 6.4:
 *
 *   < 6.4   int f(int (*fn)(void *, const char *, unsigned long), void *data)
 *   >= 6.4  int f(int (*fn)(void *, const char *, struct module *,
 *                           unsigned long), void *data, struct module *mod)
 *
 * The previous version of this file had the two branches swapped, so on 6.6
 * the wrapper was typed as the three-argument form while the kernel expected
 * four: the call passed only fn and data, and the kernel read whatever was in
 * x2 as struct module *mod. Vendor 5.10/5.15 trees that backported the module
 * argument make a compile-time test insufficient either way, so the actual
 * number of arguments is decided at runtime from kver below. */
typedef int (*kp_each_2_t)(int (*fn)(void *, const char *, unsigned long),
			   void *data);
typedef int (*kp_each_3_t)(int (*fn)(void *, const char *, struct module *,
				     unsigned long),
			   void *data, struct module *mod);

/* Only meaningful for the name-lookup path below; kallsyms_lookup_name is
 * exported on GKI 5.10 so we call it directly. */
static void *kp_on_each_symbol;

unsigned long kp_resolve_symbol(const char *name)
{
	return kallsyms_lookup_name(name);
}

struct kp_variant_ctx {
	const char *name;
	size_t name_len;
	unsigned long exact;
	unsigned long variant;
};

static int kp_variant_match(void *data, const char *name, unsigned long addr)
{
	struct kp_variant_ctx *ctx = data;
	size_t nlen;

	if (!name || !addr)
		return 0;
	nlen = strlen(name);

	if (!strcmp(name, ctx->name)) {
		ctx->exact = addr;
		return 1; /* exact match is always best; stop */
	}
	if (nlen > ctx->name_len && !strncmp(name, ctx->name, ctx->name_len) &&
	    (name[ctx->name_len] == '.' || name[ctx->name_len] == '

void *kp_resolve_symbol_variant(const char *name)
{
	/* Traditional CFI (< 6.1) requires calling functions through their .cfi_jt
	 * canonical-jump-table entry, not the function body - a direct indirect
	 * call to the body trips __cfi_check (panic). Prefer the .cfi_jt variant,
	 * then the exact symbol, then any .llvm.<hash> mangled name. */
	char cfi_name[KSYM_NAME_LEN];
	int n = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", name);
	if (n > 0 && n < (int)sizeof(cfi_name)) {
		unsigned long jt = kallsyms_lookup_name(cfi_name);
		if (jt)
			return (void *)jt;
	}

	struct kp_variant_ctx ctx = { .name = name, .name_len = strlen(name) };

	ctx.exact = kallsyms_lookup_name(name);
	if (ctx.exact)
		return (void *)ctx.exact;
	if (kp_on_each_symbol) {
		/* Pick the call shape from the RUNNING kernel, not the build header:
		 * a vendor 5.10 may carry the three-argument backport, and a 6.6 always
		 * has it. Passing the wrong count leaves x2 holding whatever the
		 * compiler left there, which the kernel then uses as struct module *. */
		if (kver >= VERSION(6, 4, 0)) {
			int visited = (int)((kp_each_3_t)kp_on_each_symbol)(
				kp_variant_cb4, &ctx, NULL);
			(void)visited;
		} else {
			int visited = (int)((kp_each_2_t)kp_on_each_symbol)(
				kp_variant_cb3, &ctx);
			(void)visited;
		}
		return (void *)ctx.variant;
	}
	return NULL;
}

void kp_symres_init(void)
{
	kp_on_each_symbol = (void *)kallsyms_lookup_name("kallsyms_on_each_symbol");
	logki("symbol resolver ready (on_each_symbol=%px)\n", kp_on_each_symbol);
}
)) {
		if (!ctx->variant)
			ctx->variant = addr;
	}
	return 0;
}

/* Two thin wrappers so each call shape has a callback of the matching type;
 * kCFI checks the hash at the indirect call, so one function cannot serve
 * both prototypes. */
static int kp_variant_cb3(void *data, const char *name, unsigned long addr)
{
	return kp_variant_match(data, name, addr);
}

static int kp_variant_cb4(void *data, const char *name, struct module *m,
			  unsigned long addr)
{
	(void)m;
	return kp_variant_match(data, name, addr);
}

void *kp_resolve_symbol_variant(const char *name)
{
	/* Traditional CFI (< 6.1) requires calling functions through their .cfi_jt
	 * canonical-jump-table entry, not the function body - a direct indirect
	 * call to the body trips __cfi_check (panic). Prefer the .cfi_jt variant,
	 * then the exact symbol, then any .llvm.<hash> mangled name. */
	char cfi_name[KSYM_NAME_LEN];
	int n = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", name);
	if (n > 0 && n < (int)sizeof(cfi_name)) {
		unsigned long jt = kallsyms_lookup_name(cfi_name);
		if (jt)
			return (void *)jt;
	}

	struct kp_variant_ctx ctx = { .name = name, .name_len = strlen(name) };

	ctx.exact = kallsyms_lookup_name(name);
	if (ctx.exact)
		return (void *)ctx.exact;
	if (kp_on_each_symbol) {
		/* Pick the call shape from the RUNNING kernel, not the build header:
		 * a vendor 5.10 may carry the three-argument backport, and a 6.6 always
		 * has it. Passing the wrong count leaves x2 holding whatever the
		 * compiler left there, which the kernel then uses as struct module *. */
		if (kver >= VERSION(6, 4, 0)) {
			int visited = (int)((kp_each_3_t)kp_on_each_symbol)(
				kp_variant_cb4, &ctx, NULL);
			(void)visited;
		} else {
			int visited = (int)((kp_each_2_t)kp_on_each_symbol)(
				kp_variant_cb3, &ctx);
			(void)visited;
		}
		return (void *)ctx.variant;
	}
	return NULL;
}

void kp_symres_init(void)
{
	kp_on_each_symbol = (kp_kallsyms_on_each_symbol_t)kallsyms_lookup_name("kallsyms_on_each_symbol");
	logki("symbol resolver ready (on_each_symbol=%px)\n", kp_on_each_symbol);
}
