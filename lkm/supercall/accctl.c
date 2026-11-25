// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * The ko is compiled against a fixed KMI, so struct cred fields are directly
 * addressable (KP's kpimg needs runtime cred_offset instead). Full root =
 * all capabilities + uid/gid switch via a freshly prepared cred. The SELinux
 * translabel helper is resolved at runtime like KP does.
 */
#include "accctl.h"

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <scdefs.h>
#include <hook.h>

#include "../include/kp_call.h"

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"
#include "../manager/manager.h"
#include "../supercall/sucompat.h"

/* security_secctx_to_secid is EXPORT_SYMBOL on 5.15 - link it directly. */
extern int security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);

/* selinux_blob_sizes is a global; resolve via kallsyms. cred->security is a
 * pointer to the LSM cred blob; the selinux part lives at +lbs_cred. */
struct kp_lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
};

static struct kp_lsm_blob_sizes *kp_selinux_blob_sizes;

/* task_security_struct { osid, sid, ... } - RANDSTRUCT is off, so sid is the
 * second u32 (offset 4). */
struct kp_task_sec {
	u32 osid;
	u32 sid;
};

int kp_accctl_init(void)
{
	kp_selinux_blob_sizes = (struct kp_lsm_blob_sizes *)kp_resolve_symbol("selinux_blob_sizes");
	if (!kp_selinux_blob_sizes) {
		logke("failed to resolve selinux_blob_sizes; selinux translabel disabled\n");
		return 0;
	}
	logki("selinux blob sizes: lbs_cred=%d\n", kp_selinux_blob_sizes->lbs_cred);
	return 0;
}

/* Translabel a freshly-prepared cred to the given SELinux context (5.15 has no
 * set_security_override_from_ctx; it was removed in GKI). Resolve the context
 * to a sid and write tsec->sid directly. */
static int kp_selinux_set_cred_context(struct cred *new, const char *sctx)
{
	struct kp_task_sec *tsec;
	u32 sid;
	int rc;

	if (!kp_selinux_blob_sizes || !sctx || !sctx[0])
		return -EINVAL;

	rc = security_secctx_to_secid(sctx, strlen(sctx), &sid);
	if (rc || !sid) {
		logkw("secctx_to_secid(%s) failed: %d sid=%u\n", sctx, rc, sid);
		return rc ? rc : -EINVAL;
	}

	tsec = (struct kp_task_sec *)((char *)new->security + kp_selinux_blob_sizes->lbs_cred);
	tsec->sid = sid;
	return 0;
}

/* Fill every capability in a kernel_cap_t. */
static void fill_caps(struct cred *new)
{
	kernel_cap_t all = CAP_FULL_SET;
	new->cap_effective = all;
	new->cap_permitted = all;
	new->cap_inheritable = all;
	new->cap_bset = all;
	new->cap_ambient = all;
}

static void su_cred(struct cred *new, uid_t uid)
{
	fill_caps(new);
	new->uid = make_kuid(current_user_ns(), uid);
	new->euid = new->uid;
	new->fsuid = new->uid;
	new->suid = new->uid;
	new->gid = make_kgid(current_user_ns(), uid);
	new->egid = new->gid;
	new->fsgid = new->gid;
	new->sgid = new->gid;
}

/* no_sanitize("cfi") keeps indirect calls in this function from tripping
 * __cfi_check on traditional-CFI 5.15 kernels. */
__attribute__((no_sanitize("cfi")))
static int commit_common_su(uid_t to_uid, const char *sctx)
{
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	su_cred(new, to_uid);

	/* Translabel to sctx (e.g. u:r:magisk:s0 / u:r:kp:s0). Without this the
	 * granted process keeps its untrusted_app SELinux domain while running as
	 * uid 0 with all caps - Android blocks it and the app fails to open. If
	 * translabel fails, abort the creds so the caller falls back to another
	 * domain instead of committing an untranslabelled root. */
	if (sctx && sctx[0]) {
		int rc = kp_selinux_set_cred_context(new, sctx);
		if (rc) {
			logkw("selinux set context(%s) failed: %d\n", sctx, rc);
			abort_creds(new);
			return rc;
		}
	}

	commit_creds(new);
	return 0;
}

__attribute__((no_sanitize("cfi")))
int kp_commit_su(uid_t to_uid, const char *sctx)
{
	int rc;

	/* Disable seccomp on the caller, matching KP's commit_common_su. */
	current_thread_info()->flags &= ~_TIF_SECCOMP;

	/* Empty sctx: default to the magisk domain (KP initializes all_allow_sctx
	 * to ALL_ALLOW_SCONTEXT_MAGISK). The u:r:kernel:s0 domain cannot connect
	 * sockets or run ART (seen: libsu RootServer ClassNotFoundException after
	 * Natives.su(0,null) granted kernel cred). Use the fully-qualified
	 * u:r:magisk:s0, resolved via security_secctx_to_secid. Fall back to
	 * kernel cred only if the domain is unavailable. */
	if (!sctx || !sctx[0]) {
		if (kp_selinux_blob_sizes) {
			rc = commit_common_su(to_uid, ALL_ALLOW_SCONTEXT_MAGISK);
			if (!rc) {
				logki("commit_su: to_uid=%u magisk domain\n", to_uid);
				return 0;
			}
			logkw("magisk domain translabel failed (%d), kernel cred fallback\n", rc);
		}
		struct cred *new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;
		commit_creds(new);
		logki("commit_su: to_uid=%u kernel cred (u:r:kernel:s0)\n", to_uid);
		return 0;
	}

	/* Explicit sctx: try the translabel, fall back to kernel cred if it fails
	 * so the caller still gets root. */
	rc = commit_common_su(to_uid, sctx);
	if (rc) {
		logkw("commit_common_su failed (%d), falling back to kernel cred\n", rc);
		struct cred *new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;
		commit_creds(new);
		return 0;
	}
	return 0;
}

/* ---- SELinux enforcement bypass ---------------------------------------
 *
 * Ported from kernel/patch/common/accctl.c bypass_selinux(). Same reason it
 * exists there: kp_commit_su() can set uid and capabilities, but an
 * untrusted_app domain that suddenly runs as uid 0 is still denied by SELinux
 * for the operations root needs (open /data/adb, mount, socket). The
 * translabel in kp_selinux_set_cred_context() covers the common case; this is
 * the second layer for ROMs where the magisk domain does not exist and the
 * translabel had to fall back to kernel creds.
 *
 * Every argument is void* on purpose. avc_denied() and slow_avc_audit() take
 * struct av_decision / struct common_audit_data, which live in
 * security/selinux/avc.h - a kernel-private header an out-of-tree module
 * cannot include. KP carries its own copy of those headers because it builds
 * against a vendored tree; the LKM does not, so it passes the pointers through
 * untouched and only writes the two words it actually needs at the two offsets
 * the struct layout guarantees (allowed / auditallow / auditdeny are the first
 * three u32 of av_decision, in that order, on every supported kernel).
 */
struct kp_av_decision_head {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
};

typedef int (*kp_avc_denied_t)(void *ssid, void *tsid, void *tclass, void *requested,
			       void *driver, void *xperm, void *flags, void *avd);
typedef int (*kp_slow_avc_audit_t)(void *ssid, void *tsid, void *tclass, void *requested,
				   void *audited, void *denied, void *result, void *a);

static kp_avc_denied_t kp_avc_denied_orig;
static kp_slow_avc_audit_t kp_slow_avc_audit_orig;
static bool kp_selinux_bypass_on;

/* Only the manager and the uids it granted root to get denials turned into
 * grants. Everything else keeps the stock decision. */
static bool kp_selinux_bypass_current(void)
{
	uid_t uid;

	if (!READ_ONCE(kp_selinux_bypass_on))
		return false;
	uid = from_kuid(current_user_ns(), current_uid());
	return kp_is_su_allow_uid(uid) || kp_is_manager_uid(uid);
}

__attribute__((no_sanitize("cfi")))
static int kp_avc_denied_hook(void *ssid, void *tsid, void *tclass, void *requested,
			      void *driver, void *xperm, void *flags, void *avd)
{
	if (avd && kp_selinux_bypass_current()) {
		struct kp_av_decision_head *d = (struct kp_av_decision_head *)avd;
		d->allowed = 0xffffffffu;
		d->auditallow = 0;
		d->auditdeny = 0;
		return 0;
	}
	if (!kp_avc_denied_orig)
		return -EACCES;
	/* Through kp_call8, not a C call: kp_avc_denied_orig is hook()'s
	 * relocated original, i.e. instruction bytes with no KCFI type hash in
	 * front of them. A C-level call would load the hash, fail, and panic
	 * with "Oops - CFI" on the first stat() of the boot. See kp_call.h. */
	return (int)kp_call8((void *)kp_avc_denied_orig,
			     (unsigned long)ssid, (unsigned long)tsid,
			     (unsigned long)tclass, (unsigned long)requested,
			     (unsigned long)driver, (unsigned long)xperm,
			     (unsigned long)flags, (unsigned long)avd);
}

__attribute__((no_sanitize("cfi")))
static int kp_slow_avc_audit_hook(void *ssid, void *tsid, void *tclass, void *requested,
				  void *audited, void *denied, void *result, void *a)
{
	/* Swallow the audit record for bypassed callers: a grant that still emits
	 * an avc denial line is itself a detection signal. */
	if (kp_selinux_bypass_current())
		return 0;
	if (!kp_slow_avc_audit_orig)
		return (int)(long)result;
	return (int)kp_call8((void *)kp_slow_avc_audit_orig,
			     (unsigned long)ssid, (unsigned long)tsid,
			     (unsigned long)tclass, (unsigned long)requested,
			     (unsigned long)audited, (unsigned long)denied,
			     (unsigned long)result, (unsigned long)a);
}

int kp_selinux_bypass_init(void)
{
	unsigned long addr;
	hook_err_t rc;

	addr = kp_resolve_symbol("avc_denied");
	if (addr) {
		rc = hook((void *)addr, (void *)kp_avc_denied_hook,
			  (void **)&kp_avc_denied_orig);
		if (rc == HOOK_NO_ERR)
			logki("avc_denied hooked at %px (orig %px)\n",
			      (void *)addr, (void *)kp_avc_denied_orig);
		else
			logkw("hook avc_denied(%px) failed: %d\n", (void *)addr, rc);
	} else {
		logkw("avc_denied not found; denial bypass unavailable\n");
	}

	addr = kp_resolve_symbol("slow_avc_audit");
	if (addr) {
		rc = hook((void *)addr, (void *)kp_slow_avc_audit_hook,
			  (void **)&kp_slow_avc_audit_orig);
		if (rc == HOOK_NO_ERR)
			logki("slow_avc_audit hooked at %px (orig %px)\n",
			      (void *)addr, (void *)kp_slow_avc_audit_orig);
		else
			logkw("hook slow_avc_audit(%px) failed: %d\n", (void *)addr, rc);
	}

	WRITE_ONCE(kp_selinux_bypass_on, true);
	return 0;
}

int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
	struct task_struct *task;
	const struct cred *old;
	struct cred *new;

	task = find_get_task_by_vpid(pid);
	if (!task) {
		logke("task_su: no task pid %d\n", pid);
		return -ESRCH;
	}

	new = prepare_creds();
	if (!new) {
		put_task_struct(task);
		return -ENOMEM;
	}
	su_cred(new, to_uid);
	(void)sctx;

	rcu_read_lock();
	old = task->cred;
	rcu_assign_pointer(task->cred, new);
	rcu_assign_pointer(task->real_cred, new);
	rcu_read_unlock();
	put_cred(old);

	put_task_struct(task);
	logki("task_su: pid %d -> uid %u\n", pid, to_uid);
	return 0;
}
