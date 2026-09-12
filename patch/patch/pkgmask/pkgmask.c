// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask - built-in kernel package hiding for Android arm64 / GKI 6.6
 *
 * Built into the kernel image (obj-y), NOT a loadable module.
 *
 * Mechanism (v3.2):
 *   1. filldir64 / filldir filtering (fs/readdir.c)
 *        - The core kernel calls pkgmask_filter_dirent(name, dir) for every
 *          directory entry; pkgmask returns true for hidden entries and the
 *          entry is dropped.  This replaces the v3.0/3.1 kretprobe on
 *          __arm64_sys_getdents64, which failed (-EINVAL/-EEXIST) on kernels
 *          where SUSFS/KPM already occupies that ftrace slot.
 *        - fs/readdir.c defines a __weak default returning false; this
 *          built-in module provides the strong definition, so the kernel
 *          links whether or not pkgmask is enabled.
 *   2. LSM hooks              - inode_permission / inode_getattr deny
 *                               (stat / open / access -> ENOENT)
 *   3. __arm64_sys_* path kretprobes as fallback (optional, off by default)
 *
 * Zero-width character variants of a hidden path resolve to the same inode,
 * so matching on (dev, ino) hides every spelling identically.
 *
 * Configuration interface (live, no reboot):
 *   /sys/module/pkgmask/parameters/target_paths   comma-separated abs paths
 *   /sys/module/pkgmask/parameters/deny_uids      comma-separated UIDs
 *   /sys/module/pkgmask/parameters/allow_uids     comma-separated UIDs
 *   /sys/module/pkgmask/parameters/scope_mode     global | deny | allow
 *   /sys/module/pkgmask/parameters/hide_dirents   0/1
 *   /sys/module/pkgmask/parameters/hook_perm      0/1
 *   /sys/module/pkgmask/parameters/hook_getattr   0/1
 *   /sys/module/pkgmask/parameters/hook_getdents  0/1  (drives filldir64)
 *   /sys/module/pkgmask/parameters/syscall_hooks  comma list or empty
 *   /sys/module/pkgmask/parameters/reload         write "1" to (re)apply
 *   /sys/module/pkgmask/parameters/status         read-only state dump
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/version.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

/*
 * close_fd() is defined in fs/file.c (EXPORT_SYMBOL) but its declaration
 * lives in fs/file.h, an internal header drivers cannot include.
 * Declare it explicitly here.
 */
extern int close_fd(unsigned int fd);

#define PM_LOG_PREFIX "pmk: "
#define MAX_HIDE_TARGETS 64
#define MAX_DENY_UIDS 1024
#define TARGET_PATHS_LEN 4096
#define TARGET_TEXT_LEN 256
#define UID_LIST_LEN 8192
#define PM_SYSCALL_HOOKS_LEN 256
#define ANDROID_USER_OFFSET 100000u

/* ------------------------- tunables (sysfs) ------------------------- */

static bool hide_dirents = true;
module_param(hide_dirents, bool, 0600);
MODULE_PARM_DESC(hide_dirents, "Hide target from directory listings");

static bool hook_perm = true;
module_param(hook_perm, bool, 0600);
MODULE_PARM_DESC(hook_perm, "Enable inode_permission LSM hook");

static bool hook_getattr = true;
module_param(hook_getattr, bool, 0600);
MODULE_PARM_DESC(hook_getattr, "Enable inode_getattr LSM hook");

static bool hook_getdents;
module_param(hook_getdents, bool, 0600);
MODULE_PARM_DESC(hook_getdents, "Enable filldir64/filldir listing filter");

static bool enable_syscall_hooks;
module_param(enable_syscall_hooks, bool, 0600);
MODULE_PARM_DESC(enable_syscall_hooks, "Master toggle for syscall fallback");

static char scope_mode[16] = "deny";
module_param_string(scope_mode, scope_mode, sizeof(scope_mode), 0600);
MODULE_PARM_DESC(scope_mode, "Hide scope: global, deny, or allow");

static char deny_uids[UID_LIST_LEN];
module_param_string(deny_uids, deny_uids, sizeof(deny_uids), 0600);
MODULE_PARM_DESC(deny_uids, "Comma-separated scope UIDs");

static char allow_uids[UID_LIST_LEN];
module_param_string(allow_uids, allow_uids, sizeof(allow_uids), 0600);
MODULE_PARM_DESC(allow_uids, "Comma-separated exempt UIDs");

static char target_paths[TARGET_PATHS_LEN];
module_param_string(target_paths, target_paths, sizeof(target_paths), 0600);
MODULE_PARM_DESC(target_paths, "Comma-separated absolute paths to hide");

static char syscall_hooks[PM_SYSCALL_HOOKS_LEN];
module_param_string(syscall_hooks, syscall_hooks, sizeof(syscall_hooks), 0600);
MODULE_PARM_DESC(syscall_hooks, "Comma-separated syscall fallback subset");

#define MAX_BINDER_HIDE_PKGS 16
#define BINDER_PKG_NAME_LEN 128
#define BINDER_MAX_SCAN_SIZE	(2 * 1024 * 1024)
static char binder_hide_pkg_list[MAX_BINDER_HIDE_PKGS][BINDER_PKG_NAME_LEN];
static unsigned int binder_hide_pkg_count;

static char binder_hide_packages[1024];
module_param_string(binder_hide_packages, binder_hide_packages,
		    sizeof(binder_hide_packages), 0600);
MODULE_PARM_DESC(binder_hide_packages,
		 "Comma-separated package names hidden from scope UIDs over Binder");

static bool binder_enabled = true;
module_param(binder_enabled, bool, 0600);
MODULE_PARM_DESC(binder_enabled, "Master toggle for Binder reply scrubbing");

/* --------------------------- state --------------------------- */

enum pkgmask_scope_mode {
	SCOPE_GLOBAL = 0,
	SCOPE_DENY,
	SCOPE_ALLOW,
};

struct hidden_target {
	dev_t dev;
	unsigned long long ino;
	char path[TARGET_TEXT_LEN];
	bool inode_ok;
	/* v3.2: parent directory (dev, ino) + dirent name for readdir filter */
	dev_t parent_dev;
	unsigned long long parent_ino;
	char name[TARGET_TEXT_LEN];
	bool parent_ok;
};

static struct hidden_target targets[MAX_HIDE_TARGETS];
static unsigned int target_count;

static enum pkgmask_scope_mode active_scope = SCOPE_DENY;
static uid_t deny_uid_list[MAX_DENY_UIDS];
static unsigned int deny_uid_count;
static uid_t allow_uid_list[MAX_DENY_UIDS];
static unsigned int allow_uid_count;

#define PM_ALIAS_CANDIDATES 3
static const char *const pm_alias_candidates[PM_ALIAS_CANDIDATES] = {
	"/data/data",
	"/data/user/0",
	"/data/user_de/0",
};

/* --------------------------- matching --------------------------- */

static inline bool is_target_inode(const struct inode *inode)
{
	unsigned int i;

	if (!inode || !inode->i_sb)
		return false;

	for (i = 0; i < target_count; i++) {
		if (!targets[i].inode_ok)
			continue;
		if (inode->i_ino == targets[i].ino &&
		    inode->i_sb->s_dev == targets[i].dev)
			return true;
	}

	return false;
}

static inline bool is_in_uid_list(uid_t uid)
{
	unsigned int i;

	for (i = 0; i < deny_uid_count; i++)
		if (uid == deny_uid_list[i])
			return true;
	return false;
}

static inline bool is_in_allow_list(uid_t uid)
{
	unsigned int i;

	for (i = 0; i < allow_uid_count; i++)
		if (uid == allow_uid_list[i])
			return true;
	return false;
}

static inline bool should_hide_for_current(void)
{
	uid_t uid, euid, fsuid;

	if (active_scope == SCOPE_GLOBAL)
		return true;

	uid = __kuid_val(current_uid());
	euid = __kuid_val(current_euid());
	fsuid = __kuid_val(current_fsuid());

	if (active_scope == SCOPE_ALLOW)
		return !(is_in_allow_list(uid) || is_in_allow_list(euid) ||
			 is_in_allow_list(fsuid));

	return is_in_uid_list(uid) || is_in_uid_list(euid) ||
	       is_in_uid_list(fsuid);
}

/* --------------------- LSM hooks (inode_permission / inode_getattr) --------------------- */

static bool lsm_registered;

static int pkgmask_lsm_inode_permission(struct inode *inode, int mask)
{
	if (!lsm_registered || !target_count || !hook_perm)
		return 0;

	if (should_hide_for_current() && is_target_inode(inode))
		return -ENOENT;

	return 0;
}

static int pkgmask_lsm_inode_getattr(const struct path *path)
{
	struct inode *inode = NULL;

	if (!lsm_registered || !target_count || !hook_getattr)
		return 0;

	if (path && path->dentry)
		inode = d_inode(path->dentry);

	if (should_hide_for_current() && is_target_inode(inode))
		return -ENOENT;

	return 0;
}

static struct security_hook_list pkgmask_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_permission, pkgmask_lsm_inode_permission),
	LSM_HOOK_INIT(inode_getattr, pkgmask_lsm_inode_getattr),
};

static int __init register_lsm_hooks(void)
{
	/*
	 * Vendor (OnePlus SM8750) kernel uses the legacy LSM API:
	 * security_add_hooks(hooks, count, const char *lsm);
	 * There is no struct lsm_id on this kernel.
	 */
	security_add_hooks(pkgmask_hooks, ARRAY_SIZE(pkgmask_hooks),
			   "pmk");
	lsm_registered = true;
	return 0;
}

/* --------------------------- readdir filter (v3.2) --------------------------- */

/*
 * Called from fs/readdir.c filldir64()/filldir() for every directory entry.
 * The core kernel provides a __weak default (returns false); this built-in
 * module provides the strong definition, replacing the old kretprobe on
 * __arm64_sys_getdents64 (which collides with SUSFS/KPM ftrace slots).
 *
 * Returns true when the entry must be hidden from the current caller.
 */
bool pmk_filter_dirent(const char *name, const struct inode *dir)
{
	unsigned int i;

	if (!hide_dirents || !hook_getdents || !target_count || !dir || !name)
		return false;

	if (!should_hide_for_current())
		return false;

	for (i = 0; i < target_count; i++) {
		if (!targets[i].parent_ok)
			continue;
		if (dir->i_ino == targets[i].parent_ino &&
		    dir->i_sb->s_dev == targets[i].parent_dev &&
		    strcmp(name, targets[i].name) == 0)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(pmk_filter_dirent);

/* --------------------------- syscall fallback --------------------------- */

struct syscall_match_data {
	bool matched;
	bool needs_close;
	long err;
};

static bool sys_path_matches_target(const char *p)
{
	unsigned int i;

	if (!p || p[0] != '/')
		return false;

	for (i = 0; i < target_count; i++) {
		size_t plen = strlen(targets[i].path);

		if (!plen)
			continue;
		if (strncmp(p, targets[i].path, plen) == 0) {
			char next = p[plen];

			if (!next || next == '/')
				return true;
		}
	}
	return false;
}

static bool sys_path_match_user_filename(struct pt_regs *regs)
{
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
	char buf[TARGET_TEXT_LEN];
	long len;

	if (!user_regs || !should_hide_for_current())
		return false;

	len = strncpy_from_user(buf, (const char __user *)user_regs->regs[1],
				sizeof(buf));
	if (len <= 0)
		return false;
	buf[sizeof(buf) - 1] = '\0';

	return sys_path_matches_target(buf);
}

static int sys_path_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct syscall_match_data *d = (struct syscall_match_data *)ri->data;

	d->matched = false;
	d->needs_close = false;
	d->err = -ENOENT;

	if (!sys_path_match_user_filename(regs))
		return 0;

	d->matched = true;
	return 0;
}

static int sys_openat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct syscall_match_data *d = (struct syscall_match_data *)ri->data;

	d->matched = false;
	d->needs_close = false;
	d->err = -ENOENT;

	if (!sys_path_match_user_filename(regs))
		return 0;

	d->matched = true;
	d->needs_close = true;
	return 0;
}

static int sys_openat2_entry(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	return sys_openat_entry(ri, regs);
}

static int sys_path_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct syscall_match_data *d = (struct syscall_match_data *)ri->data;
	long ret = (long)regs->regs[0];

	if (!d->matched)
		return 0;

	if (d->needs_close && ret >= 0)
		close_fd((unsigned int)ret);

	regs_set_return_value(regs, d->err);
	return 0;
}

typedef int (*pm_syscall_entry_t)(struct kretprobe_instance *,
				  struct pt_regs *);

static struct pm_syscall_probe {
	const char *symbol;
	const char *short_name;
	pm_syscall_entry_t entry;
	struct kretprobe rp;
	bool registered;
	bool enabled;
} pm_syscall_probes[] = {
	{ .symbol = "__arm64_sys_newfstatat", .short_name = "newfstatat",
	  .entry = sys_path_entry   },
	{ .symbol = "__arm64_sys_statx",      .short_name = "statx",
	  .entry = sys_path_entry   },
	{ .symbol = "__arm64_sys_faccessat",  .short_name = "faccessat",
	  .entry = sys_path_entry   },
	{ .symbol = "__arm64_sys_faccessat2", .short_name = "faccessat2",
	  .entry = sys_path_entry   },
	{ .symbol = "__arm64_sys_readlinkat", .short_name = "readlinkat",
	  .entry = sys_path_entry   },
	{ .symbol = "__arm64_sys_openat",     .short_name = "openat",
	  .entry = sys_openat_entry },
	{ .symbol = "__arm64_sys_openat2",    .short_name = "openat2",
	  .entry = sys_openat2_entry },
};

static unsigned int parse_syscall_hooks(void)
{
	char *buf, *cursor, *item;
	bool any_token_seen = false;
	unsigned int i;
	unsigned int enabled_count = 0;

	if (!syscall_hooks[0]) {
		if (enable_syscall_hooks) {
			for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++)
				pm_syscall_probes[i].enabled = true;
			return ARRAY_SIZE(pm_syscall_probes);
		}
		return 0;
	}

	buf = kstrdup(syscall_hooks, GFP_KERNEL);
	if (!buf) {
		pr_warn(PM_LOG_PREFIX "kstrdup(syscall_hooks) failed\n");
		return 0;
	}

	cursor = buf;
	while ((item = strsep(&cursor, ",")) != NULL) {
		item = strim(item);
		if (!*item)
			continue;
		any_token_seen = true;

		if (!strcmp(item, "all")) {
			for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++)
				pm_syscall_probes[i].enabled = true;
			continue;
		}
		if (!strcmp(item, "none")) {
			for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++)
				pm_syscall_probes[i].enabled = false;
			continue;
		}

		for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++) {
			if (!strcmp(item, pm_syscall_probes[i].short_name)) {
				pm_syscall_probes[i].enabled = true;
				break;
			}
		}
		if (i == ARRAY_SIZE(pm_syscall_probes))
			pr_warn(PM_LOG_PREFIX
				"unknown syscall_hooks token '%s'\n", item);
	}

	kfree(buf);

	if (!any_token_seen) {
		if (enable_syscall_hooks) {
			for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++)
				pm_syscall_probes[i].enabled = true;
			return ARRAY_SIZE(pm_syscall_probes);
		}
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++)
		if (pm_syscall_probes[i].enabled)
			enabled_count++;
	return enabled_count;
}

static void register_syscall_hooks(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++) {
		struct pm_syscall_probe *p = &pm_syscall_probes[i];
		int ret;

		if (!p->enabled || p->registered)
			continue;

		p->rp.kp.symbol_name = p->symbol;
		p->rp.entry_handler = p->entry;
		p->rp.handler = sys_path_exit;
		p->rp.data_size = sizeof(struct syscall_match_data);
		p->rp.maxactive = 40;

		ret = register_kretprobe(&p->rp);
		if (ret) {
			pr_warn(PM_LOG_PREFIX
				"register_kretprobe(%s) failed: %d\n",
				p->symbol, ret);
			continue;
		}
		p->registered = true;
	}
}

/* --------------------------- target resolution --------------------------- */

static void record_parent_info(struct hidden_target *t, struct dentry *dentry)
{
	struct inode *pinode;
	const unsigned char *dname;

	if (!t || !dentry)
		return;

	pinode = d_inode(dentry->d_parent);
	if (pinode && pinode->i_sb) {
		t->parent_ino = pinode->i_ino;
		t->parent_dev = pinode->i_sb->s_dev;
		t->parent_ok = pinode->i_ino != 0;
	}

	dname = dentry->d_name.name;
	if (dname && dname[0])
		strscpy(t->name, dname, sizeof(t->name));
}

static int add_target_path(const char *path_name)
{
	struct path path;
	struct inode *inode;
	int ret;
	unsigned int i;

	if (target_count >= MAX_HIDE_TARGETS) {
		pr_warn(PM_LOG_PREFIX "too many targets, skip %s\n", path_name);
		return -ENOSPC;
	}

	ret = kern_path(path_name, LOOKUP_FOLLOW, &path);
	if (ret) {
		pr_warn(PM_LOG_PREFIX "%s not found (err=%d), skip\n",
			path_name, ret);
		return ret;
	}

	inode = d_inode(path.dentry);
	if (!inode || !inode->i_sb) {
		path_put(&path);
		return -ENOENT;
	}

	/* Dedup by (dev, ino). */
	for (i = 0; i < target_count; i++) {
		if (targets[i].ino == inode->i_ino &&
		    targets[i].dev == inode->i_sb->s_dev) {
			path_put(&path);
			return 0;
		}
	}

	targets[target_count].ino = inode->i_ino;
	targets[target_count].dev = inode->i_sb->s_dev;
	targets[target_count].inode_ok = inode->i_ino != 0;
	strscpy(targets[target_count].path, path_name,
		sizeof(targets[target_count].path));
	record_parent_info(&targets[target_count], path.dentry);
	target_count++;
	path_put(&path);

	/*
	 * Alias expansion: /data/data/<pkg> is reachable through several
	 * bind-mount spellings; hide the same dir under the siblings too.
	 */
	for (i = 0; i < ARRAY_SIZE(pm_alias_candidates); i++) {
		char alias[TARGET_TEXT_LEN];
		size_t plen = strlen(pm_alias_candidates[i]);
		unsigned int j;

		if (strncmp(path_name, pm_alias_candidates[i], plen) ||
		    (path_name[plen] != '/' && path_name[plen] != '\0'))
			continue;

		for (j = 0; j < ARRAY_SIZE(pm_alias_candidates); j++) {
			size_t alen;
			struct path apath;
			struct inode *ainode;

			if (j == i)
				continue;

			alen = strlen(pm_alias_candidates[j]);
			if (!strncmp(path_name, pm_alias_candidates[j], alen) &&
			    (path_name[alen] == '/' || path_name[alen] == '\0'))
				continue; /* already this spelling */

			if (target_count >= MAX_HIDE_TARGETS)
				break;

			if (alen + strlen(path_name + plen) + 1 >
			    sizeof(alias))
				continue;

			memmove(alias, pm_alias_candidates[j], alen);
			strcpy(alias + alen, path_name + plen);

			if (kern_path(alias, LOOKUP_FOLLOW, &apath))
				continue;

			ainode = d_inode(apath.dentry);
			if (ainode && ainode->i_sb &&
			    (ainode->i_ino != inode->i_ino ||
			     ainode->i_sb->s_dev != inode->i_sb->s_dev)) {
				targets[target_count].ino = ainode->i_ino;
				targets[target_count].dev = ainode->i_sb->s_dev;
				targets[target_count].inode_ok =
					ainode->i_ino != 0;
				strscpy(targets[target_count].path, alias,
					sizeof(targets[target_count].path));
				record_parent_info(&targets[target_count],
						   apath.dentry);
				target_count++;
			}
			path_put(&apath);
		}
		break;
	}

	return 0;
}

static int resolve_target_paths(const char *paths)
{
	char *buf, *cursor, *item;
	int ret = -ENOENT;

	buf = kstrdup(paths, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cursor = buf;
	while ((item = strsep(&cursor, ",")) != NULL) {
		item = strim(item);
		if (!*item)
			continue;

		ret = add_target_path(item);
		if (ret && target_count == 0)
			continue;
	}

	kfree(buf);

	if (!target_count)
		return ret;

	return 0;
}

static int parse_scope_mode(void)
{
	char *m = strim(scope_mode);

	if (!strcmp(m, "global")) {
		active_scope = SCOPE_GLOBAL;
		return 0;
	}
	if (!strcmp(m, "deny")) {
		active_scope = SCOPE_DENY;
		return 0;
	}
	if (!strcmp(m, "allow")) {
		active_scope = SCOPE_ALLOW;
		return 0;
	}

	pr_err(PM_LOG_PREFIX "unsupported scope_mode=%s\n", m);
	return -EINVAL;
}

static int add_uid_to_list(uid_t uid, bool allow)
{
	uid_t *list = allow ? allow_uid_list : deny_uid_list;
	unsigned int *count = allow ? &allow_uid_count : &deny_uid_count;
	unsigned int i;

	if (*count >= MAX_DENY_UIDS)
		return -ENOSPC;

	for (i = 0; i < *count; i++)
		if (list[i] == uid)
			return 0;

	list[(*count)++] = uid;
	return 0;
}

static int parse_uid_list(const char *src, bool allow)
{
	char *buf, *cursor, *item;
	int ret = 0;

	if (!src || !src[0])
		return 0;

	buf = kstrdup(src, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cursor = buf;
	while ((item = strsep(&cursor, ",")) != NULL) {
		unsigned int uid;

		item = strim(item);
		if (!*item)
			continue;

		ret = kstrtouint(item, 10, &uid);
		if (ret) {
			pr_warn(PM_LOG_PREFIX "invalid uid %s\n", item);
			continue;
		}

		add_uid_to_list((uid_t)uid, allow);
	}

	kfree(buf);
	return 0;
}

static int parse_binder_packages(void)
{
	char *buf, *cursor, *item;
	unsigned int i = 0;

	binder_hide_pkg_count = 0;
	if (!binder_hide_packages[0])
		return 0;

	buf = kstrdup(binder_hide_packages, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cursor = buf;
	while ((item = strsep(&cursor, ",")) != NULL) {
		item = strim(item);
		if (!*item)
			continue;
		if (i >= MAX_BINDER_HIDE_PKGS) {
			pr_warn(PM_LOG_PREFIX "binder pkg list truncated\n");
			break;
		}
		if (strlen(item) >= BINDER_PKG_NAME_LEN) {
			pr_warn(PM_LOG_PREFIX "binder pkg too long: %.48s\n",
				item);
			continue;
		}
		strscpy(binder_hide_pkg_list[i], item, BINDER_PKG_NAME_LEN);
		i++;
	}
	binder_hide_pkg_count = i;
	kfree(buf);
	return 0;
}

/* --------------------------- apply / reload --------------------------- */

static void reset_state(void)
{
	target_count = 0;
	deny_uid_count = 0;
	allow_uid_count = 0;
}

static int apply_config(void)
{
	int ret;
	const char *paths = target_paths[0] ? target_paths : NULL;

	/*
	 * readdir filtering and LSM hooks consult the live config on every
	 * call; the optional syscall kretprobes are registered at most once
	 * and never unregistered.  Reload only refreshes the match data.
	 */
	reset_state();

	ret = parse_scope_mode();
	if (ret)
		return ret;

	ret = parse_uid_list(deny_uids, false);
	if (ret)
		return ret;

	ret = parse_uid_list(allow_uids, true);
	if (ret)
		return ret;

	ret = parse_binder_packages();
	if (ret)
		return ret;

	if (paths) {
		ret = resolve_target_paths(paths);
		if (ret)
			pr_warn(PM_LOG_PREFIX
				"resolve_target_paths: %d (targets=%u)\n",
				ret, target_count);
	}

	if (parse_syscall_hooks())
		register_syscall_hooks();

	return 0;
}

/* --------------------------- sysfs triggers --------------------------- */

static int pkgmask_reload_set(const char *val, const struct kernel_param *kp)
{
	bool b;
	int ret;

	ret = kstrtobool(val, &b);
	if (ret)
		return ret;
	if (!b)
		return 0;

	return apply_config();
}

static const struct kernel_param_ops reload_ops = {
	.set = pkgmask_reload_set,
	.get = param_get_bool,
};
static bool reload_trigger;
module_param_cb(reload, &reload_ops, &reload_trigger, 0600);
MODULE_PARM_DESC(reload, "Write 1 to (re)apply configuration from sysfs");

static int pkgmask_status_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE,
		"targets=%u scope=%s deny_uids=%u allow_uids=%u "
		"hooks=[perm=%d getattr=%d getdents=%d syscall=%d] binder=%u\n",
		target_count, scope_mode, deny_uid_count, allow_uid_count,
		lsm_registered ? 1 : 0, lsm_registered ? 1 : 0,
		hook_getdents ? 1 : 0, pm_syscall_probes[0].registered,
		binder_hide_pkg_count);
}

static const struct kernel_param_ops status_ops = {
	.get = pkgmask_status_get,
};
static int status_dummy;
module_param_cb(status, &status_ops, &status_dummy, 0400);
MODULE_PARM_DESC(status, "Read-only state dump");

/* --------------------------- init --------------------------- */

static int __init pkgmask_init(void)
{
	register_lsm_hooks();

	/*
	 * readdir filtering (filldir64/filldir) is compiled into fs/readdir.c
	 * and drives off hook_getdents, so no runtime registration is needed.
	 * Only the optional syscall fallback uses kretprobes, and only when
	 * the user configures syscall_hooks.
	 */
	return 0;
}

module_init(pkgmask_init);

MODULE_LICENSE("GPL");

/* --------------------------- Binder reply scrubbing --------------------------- */

/*
 * Called from drivers/android/binder.c (binder_transaction) after the outgoing
 * transaction buffer has been fully written (including deferred copies) into
 * the target's shared binder buffer.  The writer thread is the sending process
 * (usually system_server), so scope is judged by target_uid instead of current:
 * only transactions destined for a denied UID (e.g. the scanning app) are
 * scrubbed.  The target app reads this buffer through its own mmap, so editing
 * user_data in place is exactly what the receiver will see.
 *
 * Every occurrence of a hidden package name inside the Parcel is replaced in
 * place with an equal-length fake (every non-dot byte -> 'z'), preserving the
 * Parcel layout exactly: offsets stay valid, system_server is never touched and
 * no AIDL structure is parsed, so there is no crash surface.
 */
int pmk_binder_uid_matched(unsigned int uid)
{
	if (!binder_enabled || !binder_hide_pkg_count || uid < 10000)
		return 0;
	return is_in_uid_list(uid);
}
EXPORT_SYMBOL_GPL(pmk_binder_uid_matched);

int pmk_binder_filter_active(void)
{
	return binder_enabled && binder_hide_pkg_count > 0;
}
EXPORT_SYMBOL_GPL(pmk_binder_filter_active);

int pmk_filter_binder_data_for(char *data, size_t size, uid_t target_uid)
{
	unsigned int i, j;
	size_t nlen;
	char fake[BINDER_PKG_NAME_LEN];
	bool modified = false;

	if (!binder_enabled || !data || !size)
		return 0;
	if (!binder_hide_pkg_count || !target_count)
		return 0;
	/* Safety: only ever touch normal app UIDs (uid >= 10000).
	 * Never corrupt system_server / root recipients even if the deny
	 * list accidentally contains a system UID.
	 */
	if (target_uid < 10000)
		return 0;
	/* Safety: skip oversized transactions so the binder thread never
	 * stalls while holding target locks (watchdog / freeze risk).
	 */
	if (size > BINDER_MAX_SCAN_SIZE)
		return 0;
	if (!is_in_uid_list(target_uid))
		return 0;
	pr_debug(PM_LOG_PREFIX "binder filter uid=%u size=%zu pkgs=%u\n",
		  target_uid, size, binder_hide_pkg_count);

	for (i = 0; i < binder_hide_pkg_count; i++) {
		const char *needle = binder_hide_pkg_list[i];
		if (!needle)
			continue;
		char *p = data;
		char *end;

		nlen = strnlen(needle, BINDER_PKG_NAME_LEN - 1);
		if (nlen == 0 || nlen >= size)
			continue;

		for (j = 0; j < nlen; j++)
			fake[j] = (needle[j] == '.') ? '.' : 'z';
		fake[nlen] = '\0';

		end = data + size - nlen;
		while (p <= end) {
			p = memchr(p, needle[0], end - p + 1);
			if (!p)
				break;
			if (memcmp(p, needle, nlen) == 0) {
				memcpy(p, fake, nlen);
				modified = true;
				p += nlen;
			} else {
				p++;
			}
		}
	}
	return modified ? 1 : 0;
}
EXPORT_SYMBOL_GPL(pmk_filter_binder_data_for);
