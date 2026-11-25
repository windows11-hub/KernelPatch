/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Credential switching and SELinux enforcement bypass. Ported from
 * kernel/patch/common/accctl.c; the ko is KMI-bound so struct cred fields are
 * addressed directly instead of through KP's runtime cred_offset.
 */
#ifndef _KP_LKM_ACCCTL_H_
#define _KP_LKM_ACCCTL_H_
#include <linux/types.h>

/* Resolve the SELinux translabel helper at init. */
int kp_accctl_init(void);

/* Hook avc_denied / slow_avc_audit so a denial for a root-granted uid is
 * decided as an allow and not audited. Must run after kp_hook_runtime_init(). */
int kp_selinux_bypass_init(void);

/* Grant root to the current task (uid/gid -> to_uid, all caps). */
int kp_commit_su(uid_t to_uid, const char *sctx);

/* Grant root to another task by pid. */
int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx);

#endif /* _KP_LKM_ACCCTL_H_ */
