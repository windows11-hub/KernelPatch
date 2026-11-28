/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Credential switching. Ported from kernel/patch/common/accctl.c; the ko is
 * KMI-bound so struct cred fields are addressed directly instead of through
 * KP's runtime cred_offset.
 *
 * The SELinux enforcement bypass (avc_denied / slow_avc_audit hooks) that this
 * header used to declare is gone. selinux_hook answers the same queries from
 * the opposite direction - it returns the clean-policy result rather than
 * forcing an allow - and running both would make compute_av and avc_has_perm
 * disagree, which is exactly the inconsistency signal a detector keys on.
 */
#ifndef _KP_LKM_ACCCTL_H_
#define _KP_LKM_ACCCTL_H_
#include <linux/types.h>

/* Resolve the SELinux translabel helper at init. */
int kp_accctl_init(void);

/* Grant root to the current task (uid/gid -> to_uid, all caps). */
int kp_commit_su(uid_t to_uid, const char *sctx);

/* Grant root to another task by pid. */
int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx);

#endif /* _KP_LKM_ACCCTL_H_ */
