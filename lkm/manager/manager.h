/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Trusted manager detection. Scans /data/app for a base.apk whose v2 signing
 * certificate matches a trusted digest, looks up the package's uid from
 * /data/system/packages.list, and records it as a manager appid. Supercalls
 * are authenticated by comparing the caller's uid against those appids.
 *
 * Multiple managers are supported: the scan collects every trusted apk it
 * finds instead of stopping at the first one, so several manager builds (or a
 * manager plus a second trusted front-end) can all drive the same kernel
 * module. The first crowned appid is also exposed through kp_manager_appid()
 * for callers that want "the" manager.
 */
#ifndef _KP_LKM_MANAGER_H_
#define _KP_LKM_MANAGER_H_
#include <linux/types.h>

#define KP_INVALID_APPID ((uid_t)-1)

/* How many distinct manager appids can be crowned at once. */
#define KP_MANAGER_MAX 8

/* Kick off the manager scan. Runs synchronously in the caller's context (the
 * root process that loaded the ko) so SELinux allows reading /data/app and
 * /data/system/packages.list - a workqueue would run in the denied kernel
 * domain. Call once from module init. */
int kp_manager_init(void);

/* Re-scan synchronously (e.g. retry if the first scan ran before the manager
 * was installed). Returns 0 if at least one manager was crowned. */
int kp_manager_refresh(void);

/* Re-scan reading the staged packages.list.tmp; called by the rename hook
 * (fires before the tmp->main rename's d_move, when .tmp holds the new data). */
int kp_manager_refresh_from_packages_list_tmp(void);

/* Hook security_path_rename (fallback security_inode_rename) so a
 * packages.list.tmp rename re-derives the trusted manager uids. */
void hook_rename_lsm(void);
void hook_rename_lsm_exit(void);

/* The first crowned manager appid (KP_INVALID_APPID if none yet). */
uid_t kp_manager_appid(void);

/* Number of crowned managers and read access by index, for diagnostics. */
int kp_manager_count(void);
uid_t kp_manager_appid_at(int index);

/* True if @uid belongs to any crowned manager. */
bool kp_is_manager_uid(uid_t uid);

#endif /* _KP_LKM_MANAGER_H_ */
