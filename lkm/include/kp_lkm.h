/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch LKM common definitions: version and logging.
 */
#ifndef _KP_LKM_H_
#define _KP_LKM_H_

#include <linux/printk.h>
#include <linux/version.h>

#include "log.h"

/* Version. Kbuild reads the repo-root ../version file and passes the three
 * numbers in as -DKP_LKM_MAJOR/MINOR/PATCH, so this header can never drift
 * from it. The #ifndef fallbacks keep the file buildable standalone. */
#ifndef KP_LKM_MAJOR
#define KP_LKM_MAJOR 0
#endif
#ifndef KP_LKM_MINOR
#define KP_LKM_MINOR 13
#endif
#ifndef KP_LKM_PATCH
#define KP_LKM_PATCH 3
#endif
#define KP_LKM_VERSION_CODE ((KP_LKM_MAJOR << 16) | (KP_LKM_MINOR << 8) | KP_LKM_PATCH)
#define kpver KP_LKM_VERSION_CODE

/* "x.y.z" for MODULE_VERSION. */
#define KP_LKM_STR2(x) #x
#define KP_LKM_STR(x) KP_LKM_STR2(x)
#define KP_LKM_VERSION_STRING \
	KP_LKM_STR(KP_LKM_MAJOR) "." KP_LKM_STR(KP_LKM_MINOR) "." KP_LKM_STR(KP_LKM_PATCH)

/* kver mirrors KP: major<<16 | minor<<8 | patch. */
static inline long kp_kver(void)
{
	return (long)LINUX_VERSION_CODE;
}

/*
 * The logk* macros live in log.h and only there.
 *
 * They used to be defined in both headers with slightly different shapes
 * (this one had no __func__, log.h did), guarded with plain #define. Any
 * translation unit that pulled in hook.h - which includes log.h - and then
 * kp_lkm.h got a macro-redefinition, and the build runs with -Werror. The
 * duplicate definitions are gone; log.h is the single owner and this header
 * just re-exports it, so include order can no longer change what a log line
 * looks like.
 */
#define KPLKM_TAG "kernelpatch-lkm"

#endif /* _KP_LKM_H_ */
