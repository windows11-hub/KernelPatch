/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Calling arbitrary kernel addresses without tripping KCFI.
 *
 * Every address this module takes at runtime - kallsyms_lookup_name() results,
 * module_alloc() memory, compiled KPM images, hook()'s relocated originals -
 * is a raw number with no KCFI type hash in front of it. A C-level call
 * through such a pointer makes the compiler emit
 *
 *     ldr  w8, [x8, #-4]      ; load the type hash
 *     ...  compare against the hash baked in at the call site
 *     brk  #0x8228            ; KCFI failure
 *
 * and the comparison cannot pass, so the first such call panics the kernel.
 * That is what the log shows: "CFI failure at kp_avc_denied_hook+0xc8
 * (target: ..., expected type: 0x9840414e)" followed by "Oops - CFI".
 *
 * The fix is not to disable CFI. It is to not ask the compiler for a checked
 * call: issue the branch in inline asm. The compiler cannot instrument an
 * instruction it did not generate, so blr below performs an ordinary indirect
 * call and none of the above is emitted. This is the same technique
 * SukiSU-KPM-Module's kp_remote_call4() uses for exactly this reason, and it
 * keeps CFI enabled for all of our own code.
 *
 * The "+r" constraints force each argument register to be live and let the
 * asm update it, which is how the return value comes back on arm64 (x0).
 * x18 is deliberately absent from the clobber list: it is -ffixed as the
 * shadow call stack pointer and newer clang rejects it in clobbers.
 */
#ifndef _KP_CALL_H_
#define _KP_CALL_H_

/* No headers on purpose: this file is compiled by both the in-tree KernelPatch
 * build (which has its own types.h) and the loadable module build (which has
 * linux/types.h). Everything below uses only built-in C types, so neither
 * include path can break it. */

#if defined(__aarch64__)

#define KP_CALL_CLOBBER_COMMON \
	"x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "lr", "cc", "memory"

/* Calls @fn with 0 arguments; x0 is the return value. */
static inline unsigned long kp_call0(void *fn)
{
	register unsigned long x0 __asm__("x0") = 0;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 1 argument. */
static inline unsigned long kp_call1(void *fn, unsigned long a0)
{
	register unsigned long x0 __asm__("x0") = a0;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 2 arguments. */
static inline unsigned long kp_call2(void *fn, unsigned long a0, unsigned long a1)
{
	register unsigned long x0 __asm__("x0") = a0;
	register unsigned long x1 __asm__("x1") = a1;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0), "+r"(x1)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 3 arguments. */
static inline unsigned long kp_call3(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2)
{
	register unsigned long x0 __asm__("x0") = a0;
	register unsigned long x1 __asm__("x1") = a1;
	register unsigned long x2 __asm__("x2") = a2;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0), "+r"(x1), "+r"(x2)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 4 arguments. */
static inline unsigned long kp_call4(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2, unsigned long a3)
{
	register unsigned long x0 __asm__("x0") = a0;
	register unsigned long x1 __asm__("x1") = a1;
	register unsigned long x2 __asm__("x2") = a2;
	register unsigned long x3 __asm__("x3") = a3;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 5 arguments. */
static inline unsigned long kp_call5(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2, unsigned long a3, unsigned long a4)
{
	register unsigned long x0 __asm__("x0") = a0;
	register unsigned long x1 __asm__("x1") = a1;
	register unsigned long x2 __asm__("x2") = a2;
	register unsigned long x3 __asm__("x3") = a3;
	register unsigned long x4 __asm__("x4") = a4;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 8 arguments - the widest signature this module needs
 * (avc_denied: ssid, tsid, tclass, requested, driver, xperm, flags, avd). */
static inline unsigned long kp_call8(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2, unsigned long a3, unsigned long a4,
				     unsigned long a5, unsigned long a6, unsigned long a7)
{
	register unsigned long x0 __asm__("x0") = a0;
	register unsigned long x1 __asm__("x1") = a1;
	register unsigned long x2 __asm__("x2") = a2;
	register unsigned long x3 __asm__("x3") = a3;
	register unsigned long x4 __asm__("x4") = a4;
	register unsigned long x5 __asm__("x5") = a5;
	register unsigned long x6 __asm__("x6") = a6;
	register unsigned long x7 __asm__("x7") = a7;

	__asm__ volatile("blr %[fn]"
			 : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3),
			   "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
			 : [fn] "r"(fn)
			 : KP_CALL_CLOBBER_COMMON);
	return x0;
}

/* Calls @fn with 12 arguments.
 *
 * No inline asm here, unlike the narrower variants. AAPCS64 passes arguments
 * 9..16 on the stack, and reaching those from inline asm means adjusting sp -
 * which the compiler does not track and which is undefined behaviour. Only
 * transit12 needs this signature, and no hook in this tree takes more than 8
 * arguments (avc_denied is the widest real one), so the pragmatic answer is a
 * plain call with the per-function CFI exemption where the compiler supports
 * it. On clang 14+ no_sanitize("kcfi") suppresses the check; on older
 * toolchains there is no kcfi instrumentation to suppress in the first place.
 */
#if defined(KP_HAVE_KCFI) && KP_HAVE_KCFI
__attribute__((no_sanitize("kcfi")))
#endif
static inline unsigned long kp_call12(void *fn, unsigned long a0, unsigned long a1,
				      unsigned long a2, unsigned long a3, unsigned long a4,
				      unsigned long a5, unsigned long a6, unsigned long a7,
				      unsigned long a8, unsigned long a9, unsigned long a10,
				      unsigned long a11)
{
	return ((unsigned long (*)(unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long))fn)(
		a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

#else /* !__aarch64__ */

/* Other architectures: plain calls. They either have no KCFI or build with
 * the legacy sanitizer, which the per-object flags already handle. */
static inline unsigned long kp_call0(void *fn)
{
	return ((unsigned long (*)(void))fn)();
}
static inline unsigned long kp_call1(void *fn, unsigned long a0)
{
	return ((unsigned long (*)(unsigned long))fn)(a0);
}
static inline unsigned long kp_call2(void *fn, unsigned long a0, unsigned long a1)
{
	return ((unsigned long (*)(unsigned long, unsigned long))fn)(a0, a1);
}
static inline unsigned long kp_call3(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2)
{
	return ((unsigned long (*)(unsigned long, unsigned long, unsigned long))fn)(a0, a1, a2);
}
static inline unsigned long kp_call4(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2, unsigned long a3)
{
	return ((unsigned long (*)(unsigned long, unsigned long, unsigned long,
				   unsigned long))fn)(a0, a1, a2, a3);
}
static inline unsigned long kp_call5(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2, unsigned long a3, unsigned long a4)
{
	return ((unsigned long (*)(unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long))fn)(a0, a1, a2, a3, a4);
}
static inline unsigned long kp_call8(void *fn, unsigned long a0, unsigned long a1,
				     unsigned long a2, unsigned long a3, unsigned long a4,
				     unsigned long a5, unsigned long a6, unsigned long a7)
{
	return ((unsigned long (*)(unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long))fn)(a0, a1, a2, a3, a4,
								     a5, a6, a7);
}
static inline unsigned long kp_call12(void *fn, unsigned long a0, unsigned long a1,
				      unsigned long a2, unsigned long a3, unsigned long a4,
				      unsigned long a5, unsigned long a6, unsigned long a7,
				      unsigned long a8, unsigned long a9, unsigned long a10,
				      unsigned long a11)
{
	return ((unsigned long (*)(unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long,
				   unsigned long, unsigned long, unsigned long))fn)(
		a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

#endif /* __aarch64__ */

#endif /* _KP_CALL_H_ */
