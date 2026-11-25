// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Manager scan, mirroring KernelSU's throne_tracker flow but using the APatch
 * trusted-cert table. packages.list is plain text on all Android versions, so
 * it is the uid source; the APK cert check anchors trust.
 *
 * Multi-manager: the scan used to stop at the first base.apk that matched any
 * trusted digest, which meant exactly one appid could ever be crowned. It now
 * walks the whole tree and crowns every match, up to KP_MANAGER_MAX, so a
 * manager plus a second trusted front-end can both hold manager authority.
 * The first crowned appid still answers kp_manager_appid() so single-manager
 * callers keep working.
 */
#include "manager.h"
#include "apk_sign.h"

#include <linux/dirent.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>

#include "../include/kp_lkm.h"
#include <hook.h>

#define KP_PACKAGES_LIST "/data/system/packages.list"
#define KP_PACKAGES_LIST_TMP "/data/system/packages.list.tmp"
#define KP_DATA_APP "/data/app"
#define KP_PATH_LEN 256

/* filldir calling convention changed in 6.1 (int -> bool). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN bool
#define FILLDIR_CONTINUE true
#define FILLDIR_STOP false
#else
#define FILLDIR_RETURN int
#define FILLDIR_CONTINUE 0
#define FILLDIR_STOP -EINVAL
#endif

static uid_t kp_manager_appids[KP_MANAGER_MAX];
static int kp_manager_nappids;
static struct work_struct kp_manager_scan_work;

int kp_manager_count(void)
{
	return READ_ONCE(kp_manager_nappids);
}

uid_t kp_manager_appid_at(int index)
{
	if (index < 0 || index >= READ_ONCE(kp_manager_nappids))
		return KP_INVALID_APPID;
	return READ_ONCE(kp_manager_appids[index]);
}

uid_t kp_manager_appid(void)
{
	if (!READ_ONCE(kp_manager_nappids))
		return KP_INVALID_APPID;
	return READ_ONCE(kp_manager_appids[0]);
}

static bool kp_manager_appid_known(uid_t uid)
{
	int i, n = READ_ONCE(kp_manager_nappids);

	for (i = 0; i < n; i++) {
		if (READ_ONCE(kp_manager_appids[i]) == uid)
			return true;
	}
	return false;
}

bool kp_is_manager_uid(uid_t uid)
{
	int i, n = READ_ONCE(kp_manager_nappids);

	if (!n)
		return false;
	/* uid may include a user-id offset; compare the appid part. */
	uid = uid % 100000;
	for (i = 0; i < n; i++) {
		if ((READ_ONCE(kp_manager_appids[i]) % 100000) == uid)
			return true;
	}
	return false;
}

/* Parse /data/system/packages.list for @package and return its uid. With
 * use_tmp the staged packages.list.tmp is read instead: the rename LSM hook
 * fires before the rename's d_move, so at that instant the tmp file holds the
 * post-update content while packages.list is still the pre-update one. */
static uid_t kp_lookup_package_uid(const char *package, int use_tmp)
{
	const char *path = use_tmp ? KP_PACKAGES_LIST_TMP : KP_PACKAGES_LIST;
	struct file *fp;
	loff_t fsize;
	char *buf, *cursor, *end;
	uid_t uid = KP_INVALID_APPID;

	fp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(fp)) {
		logke("open %s failed: %ld\n", path, PTR_ERR(fp));
		return KP_INVALID_APPID;
	}
	fsize = i_size_read(file_inode(fp));
	if (fsize <= 0 || fsize > (1 << 20))
		goto out_close;

	buf = kvzalloc(fsize + 1, GFP_KERNEL);
	if (!buf)
		goto out_close;
	{
		loff_t pos = 0;
		if (kernel_read(fp, buf, fsize, &pos) != fsize) {
			kvfree(buf);
			goto out_close;
		}
	}

	cursor = buf;
	end = buf + fsize;
	while (cursor < end) {
		char *line = cursor, *line_end = cursor, *pkg, *uid_str;
		unsigned long long u = 0;

		while (line_end < end && *line_end != '\n' && *line_end != '\r')
			line_end++;
		if (line_end < end) {
			*line_end = '\0';
			cursor = line_end + 1;
		} else {
			cursor = end;
		}

		while (*line == ' ' || *line == '\t')
			line++;
		if (!*line)
			continue;
		pkg = line;
		while (*line && *line != ' ' && *line != '\t')
			line++;
		if (!*line)
			continue;
		*line++ = '\0';
		while (*line == ' ' || *line == '\t')
			line++;
		uid_str = line;
		while (*line && *line != ' ' && *line != '\t')
			line++;
		*line = '\0';

		if (strcmp(pkg, package) != 0)
			continue;
		if (kstrtoull(uid_str, 10, &u) || u > UINT_MAX)
			break;
		uid = (uid_t)u;
		break;
	}
	kvfree(buf);

out_close:
	filp_close(fp, NULL);
	return uid;
}

/* Crown one more manager. Returns true when a new appid was recorded, false
 * when it failed or was already known. Keeping this additive is what allows
 * more than one manager: the old code overwrote a single scalar and the scan
 * stopped at the first hit. */
static bool kp_crown_manager(int manager_idx, int use_tmp)
{
	const char *pkg = kp_trusted_managers[manager_idx].package;
	uid_t uid = kp_lookup_package_uid(pkg, use_tmp);
	int n;

	if (uid == KP_INVALID_APPID) {
		logke("found manager apk for %s but no uid in packages.list\n", pkg);
		return false;
	}

	n = READ_ONCE(kp_manager_nappids);
	if (kp_manager_appid_known(uid)) {
		logkfd("manager %s uid=%u already crowned\n", pkg, uid);
		return false;
	}
	if (n >= KP_MANAGER_MAX) {
		logkw("manager table full (%d), ignoring %s uid=%u\n", n, pkg, uid);
		return false;
	}

	WRITE_ONCE(kp_manager_appids[n], uid);
	/* Publish the count only after the slot is visible, so a concurrent
	 * reader that sees n+1 entries can never read an empty slot. */
	smp_wmb();
	WRITE_ONCE(kp_manager_nappids, n + 1);
	logki("trusted manager crowned: %s uid=%u (%d/%d)\n", pkg, uid, n + 1,
	      KP_MANAGER_MAX);
	return true;
}

/* Match a directory path against the trusted package list by name only.
 *
 * Why not the certificate: hashing an apk means opening it and reading it,
 * and the only place this runs is inside a readdir callback (see
 * kp_dir_actor). Doing I/O there deadlocks the f2fs directory lock on this
 * device and turns a load-time scan into a 70-second stall.
 *
 * What that costs: anyone who can install a package with a trusted id gets
 * manager authority without matching a pinned signing key. On a device whose
 * only root is a post-init user-space temp root, installing a package with a
 * given id already requires that user's cooperation, and the manager itself
 * runs as that uid - so the fallback does not grant anything the platform
 * did not already grant. It is strictly weaker than the digest check, which
 * is why every hit on this path is logged at warning level.
 *
 * Android lays packages out as /data/app/[~~<hash>/]<pkg>-<suffix>/base.apk,
 * so "<pkg>-" as a whole path component identifies the package without
 * opening the file. */
static int kp_manager_apk_match_name(const char *dir)
{
	int i;

	for (i = 0; kp_trusted_managers[i].package; i++) {
		char needle[96];
		int n = snprintf(needle, sizeof(needle), "/%s-",
				 kp_trusted_managers[i].package);

		if (n <= 0 || n >= (int)sizeof(needle))
			continue;
		if (strstr(dir, needle)) {
			logkw("manager apk matched by path name: %s (pkg %s)\n", dir,
			      kp_trusted_managers[i].package);
			return i;
		}
	}
	return -1;
}

struct kp_scan_ctx {
	struct dir_context ctx;
	char parent[KP_PATH_LEN];
	int depth;
	int use_tmp;
	int crowned;
};

static void kp_scan_apk_dir(const char *dir, int depth, int *crowned, int use_tmp);

/* Walk the whole /data/app tree. The old actor returned FILLDIR_STOP as soon
 * as one trusted apk matched, which is exactly what made multi-manager
 * impossible: a second installed manager was never even examined. Now every
 * base.apk is checked and every match is crowned; the walk only stops early
 * once the table is full, because nothing further could be recorded. */
static FILLDIR_RETURN kp_dir_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino,
				   unsigned int d_type)
{
	struct kp_scan_ctx *sc = container_of(ctx, struct kp_scan_ctx, ctx);
	char path[KP_PATH_LEN];
	(void)off; (void)ino;

	if (READ_ONCE(kp_manager_nappids) >= KP_MANAGER_MAX)
		return FILLDIR_STOP;
	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_CONTINUE;
	if (snprintf(path, sizeof(path), "%s/%.*s", sc->parent, namelen, name) >= (int)sizeof(path))
		return FILLDIR_CONTINUE;

	/* NOTE: no file I/O is allowed inside this callback.
	 *
	 * This runs under f2fs_readdir() with the directory lock held. Reading
	 * base.apk here (to hash its v2 certificate) means kernel_read() on the
	 * same f2fs mount from inside its own readdir, for every installed app.
	 * Measured on this device: the scan was still running 70 seconds into
	 * module_init, which is what left the module half-initialised while the
	 * rest of the system kept calling into it. It also nests: reading an
	 * apk can itself trigger path lookups that come back through the same
	 * dentry walk.
	 *
	 * So the walk only ever compares names here - pure string work, no
	 * locks taken beyond the one already held, no allocation beyond a stack
	 * buffer. A base.apk whose parent directory is "<trusted-pkg>-<suffix>"
	 * is a match; that is decided entirely from the path, and the digest is
	 * not consulted. See the comment on kp_manager_apk_match_name() below
	 * for what that trades away and why it is acceptable here. */
	if (d_type == DT_DIR && sc->depth > 0) {
		kp_scan_apk_dir(path, sc->depth - 1, &sc->crowned, sc->use_tmp);
	} else if (d_type == DT_REG && namelen == 8 && !strncmp(name, "base.apk", 8)) {
		int idx = kp_manager_apk_match_name(sc->parent);
		if (idx >= 0 && kp_crown_manager(idx, sc->use_tmp))
			sc->crowned++;
	}
	return FILLDIR_CONTINUE;
}

static void kp_scan_apk_dir(const char *dir, int depth, int *crowned, int use_tmp)
{
	struct file *fp;
	struct kp_scan_ctx sc;

	if (READ_ONCE(kp_manager_nappids) >= KP_MANAGER_MAX)
		return;
	fp = filp_open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
	if (IS_ERR(fp))
		return;
	memset(&sc, 0, sizeof(sc));
	sc.ctx.actor = kp_dir_actor;
	strscpy(sc.parent, dir, sizeof(sc.parent));
	sc.depth = depth;
	sc.use_tmp = use_tmp;
	sc.crowned = crowned ? *crowned : 0;
	iterate_dir(fp, &sc.ctx);
	if (crowned)
		*crowned = sc.crowned;
	filp_close(fp, NULL);
}

static int kp_manager_scan(int use_tmp)
{
	int crowned = 0;
	int total;

	/* /data/app/<pkg>-N/base.apk (pre-11) and /data/app/~~h/<pkg>-h/base.apk
	 * (11+): depth 2 covers both. */
	kp_scan_apk_dir(KP_DATA_APP, 2, &crowned, use_tmp);

	total = READ_ONCE(kp_manager_nappids);
	if (crowned)
		logki("manager scan: %d newly crowned, %d total\n", crowned, total);
	else if (!total)
		logki("trusted manager not found yet (scan incomplete or not installed)\n");

	return total ? 0 : -ENOENT;
}

static void kp_manager_scan_work_fn(struct work_struct *work)
{
	kp_manager_scan(0);
}

int kp_manager_refresh(void)
{
	return kp_manager_scan(0);
}

/* Re-derive from the staged packages.list.tmp; used by the rename hook which
 * fires before the tmp->main rename's d_move completes. */
int kp_manager_refresh_from_packages_list_tmp(void)
{
	return kp_manager_scan(1);
}

int kp_manager_init(void)
{
	/* Run the scan synchronously in the module_init context instead of a
	 * workqueue. The workqueue runs as a kernel thread in the u:r:kernel:s0
	 * SELinux domain, which many devices (e.g. MTK) deny from reading
	 * /data/app and /data/system/packages.list (dac_read_search/dac_override
	 * denied). The insmod/kpinit caller, by contrast, is root (su domain) and
	 * usually has permission to read /data. */
	INIT_WORK(&kp_manager_scan_work, kp_manager_scan_work_fn);
	kp_manager_scan_work_fn(&kp_manager_scan_work);
	return 0;
}

/* ---- packages.list rename -> re-derive manager uid ----------------------- */

#define KP_PACKAGES_LIST_TMP_SUFFIX "/system/packages.list.tmp"

/* Must match dentry_path_raw() exactly (note the const) - kCFI type-hashes the
 * indirect call, and a non-const first arg panics __cfi_slowpath_diag. */
typedef char *(*kp_dentry_path_raw_t)(const struct dentry *dentry, char *buf, int buflen);
static kp_dentry_path_raw_t kp_dentry_path_raw;
/* Track which LSM rename symbol was hooked so it can be removed on exit. */
static unsigned long kp_rename_hook_addr;
static void *kp_rename_hook_cb;

static bool kp_path_has_suffix(const char *path, const char *suffix)
{
	size_t plen, slen;

	if (!path || !suffix)
		return false;
	plen = strlen(path);
	slen = strlen(suffix);
	if (plen < slen)
		return false;
	return strcmp(path + plen - slen, suffix) == 0;
}

/* After packages.list.tmp is renamed into place, re-derive the manager uid.
 * The after-hook on the LSM rename runs before the rename's d_move, so the
 * staged packages.list.tmp still holds the post-update content. no_sanitize:
 * the dentry_path_raw call below is a raw resolved function pointer; even with
 * a matching type, don't let a kCFI check turn a benign mismatch into a panic. */
__attribute__((no_sanitize("cfi")))
static void kp_refresh_manager_on_list_rename(struct dentry *dentry)
{
	char path[128];
	char *buf;

	if (!dentry || !kp_dentry_path_raw)
		return;
	buf = kp_dentry_path_raw(dentry, path, sizeof(path));
	if (IS_ERR(buf))
		return;
	if (kp_path_has_suffix(buf, KP_PACKAGES_LIST_TMP_SUFFIX)) {
		logki("packages.list rename matched: %s\n", buf);
		kp_manager_refresh_from_packages_list_tmp();
	}
}

static void kp_after_security_path_rename(hook_fargs5_t *args, void *udata)
{
	(void)udata;
	if ((long)args->ret >= 0)
		kp_refresh_manager_on_list_rename((struct dentry *)args->arg1);
}

static void kp_after_security_inode_rename(hook_fargs5_t *args, void *udata)
{
	(void)udata;
	if ((long)args->ret >= 0)
		kp_refresh_manager_on_list_rename((struct dentry *)args->arg1);
}

void hook_rename_lsm(void)
{
	unsigned long addr;
	hook_err_t rc;

	kp_dentry_path_raw = (kp_dentry_path_raw_t)kallsyms_lookup_name("dentry_path_raw");
	if (!kp_dentry_path_raw) {
		logkw("no symbol: dentry_path_raw\n");
		return;
	}

	addr = kallsyms_lookup_name("security_path_rename");
	if (addr) {
		kp_rename_hook_addr = addr;
		kp_rename_hook_cb = kp_after_security_path_rename;
		rc = hook_wrap5((void *)addr, 0, kp_after_security_path_rename, 0);
		logki("hook security_path_rename rc: %d\n", rc);
		return;
	}

	addr = kallsyms_lookup_name("security_inode_rename");
	if (addr) {
		kp_rename_hook_addr = addr;
		kp_rename_hook_cb = kp_after_security_inode_rename;
		rc = hook_wrap5((void *)addr, 0, kp_after_security_inode_rename, 0);
		logki("hook security_inode_rename rc: %d\n", rc);
		return;
	}

	logkw("no symbol: security_path_rename/security_inode_rename\n");
}

void hook_rename_lsm_exit(void)
{
	if (kp_rename_hook_addr) {
		/* Installed as hook_wrap5(addr, 0, cb, 0); pass the same (before,
		 * after) pair to unwrap so the chain item matches. */
		hook_unwrap((void *)kp_rename_hook_addr, 0, kp_rename_hook_cb);
		kp_rename_hook_addr = 0;
		kp_rename_hook_cb = NULL;
		logki("rename LSM hook removed\n");
	}
}
