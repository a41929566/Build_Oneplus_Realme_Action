// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask - built-in kernel package hiding for Android arm64 / GKI 6.6
 *
 * Built into the kernel image (obj-y), NOT a loadable module.  This avoids
 * every insmod-side failure mode seen with the LKM build on self-compiled
 * kernels: no version magic / CRC checks, no undefined-export problems, no
 * CFI-on-indirect-call issues, no boot-time load ordering.
 *
 * What it does (same proven design as the PathMask project):
 *   1. getdents64 directory entry filtering  (scan-proof listings)
 *   2. inode_permission / vfs_getattr hooks   (stat / open / access deny)
 *   3. __arm64_sys_* path hooks as fallback   (ThinLTO-inlined paths)
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
 *   /sys/module/pkgmask/parameters/hook_getdents  0/1
 *   /sys/module/pkgmask/parameters/syscall_hooks  comma list or empty
 *   /sys/module/pkgmask/parameters/reload         write "1" to (re)apply
 *   /sys/module/pkgmask/parameters/status         read-only state dump
 *
 * At boot the module registers only the two pure-memory-read hooks
 * (inode_permission + vfs_getattr) with an empty target list, which is a
 * no-op for every process.  Configuration is applied later via sysfs
 * (typically by the paired KernelSU config-module's service.sh) which
 * triggers `reload` and resolves the target paths in normal process
 * context once /data is mounted.
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
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

#define PM_LOG_PREFIX "pkgmask: "
#define MAX_HIDE_TARGETS 64
#define MAX_DENY_UIDS 1024
#define TARGET_PATHS_LEN 4096
#define TARGET_TEXT_LEN 256
#define UID_LIST_LEN 8192
#define PM_SYSCALL_HOOKS_LEN 256
#define GETDENTS_BUF_LIMIT 65536u
#define ANDROID_USER_OFFSET 100000u

/* ------------------------- tunables (sysfs) ------------------------- */

static bool hide_dirents = true;
module_param(hide_dirents, bool, 0644);
MODULE_PARM_DESC(hide_dirents, "Hide target from getdents64 listings");

static bool hook_perm = true;
module_param(hook_perm, bool, 0644);
MODULE_PARM_DESC(hook_perm, "Enable inode_permission kretprobe");

static bool hook_getattr = true;
module_param(hook_getattr, bool, 0644);
MODULE_PARM_DESC(hook_getattr, "Enable vfs_getattr kretprobe");

static bool hook_getdents;
module_param(hook_getdents, bool, 0644);
MODULE_PARM_DESC(hook_getdents, "Enable __arm64_sys_getdents64 kretprobe");

static bool enable_syscall_hooks;
module_param(enable_syscall_hooks, bool, 0644);
MODULE_PARM_DESC(enable_syscall_hooks, "Master toggle for syscall fallback");

static char scope_mode[16] = "deny";
module_param_string(scope_mode, scope_mode, sizeof(scope_mode), 0644);
MODULE_PARM_DESC(scope_mode, "Hide scope: global, deny, or allow");

static char deny_uids[UID_LIST_LEN];
module_param_string(deny_uids, deny_uids, sizeof(deny_uids), 0644);
MODULE_PARM_DESC(deny_uids, "Comma-separated scope UIDs");

static char allow_uids[UID_LIST_LEN];
module_param_string(allow_uids, allow_uids, sizeof(allow_uids), 0644);
MODULE_PARM_DESC(allow_uids, "Comma-separated exempt UIDs");

static char target_paths[TARGET_PATHS_LEN];
module_param_string(target_paths, target_paths, sizeof(target_paths), 0644);
MODULE_PARM_DESC(target_paths, "Comma-separated absolute paths to hide");

static char syscall_hooks[PM_SYSCALL_HOOKS_LEN];
module_param_string(syscall_hooks, syscall_hooks, sizeof(syscall_hooks), 0644);
MODULE_PARM_DESC(syscall_hooks, "Comma-separated syscall fallback subset");

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

static inline bool is_target_ino(__u64 ino)
{
	unsigned int i;

	for (i = 0; i < target_count; i++) {
		if (!targets[i].inode_ok)
			continue;
		if (ino == (__u64)targets[i].ino)
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

/* --------------------- inode_permission / vfs_getattr --------------------- */

#define PM_PERM_INODE_REG 1

static struct kretprobe kp_inode_perm;
static struct kretprobe kp_inode_getattr;
static bool perm_registered;
static bool getattr_registered;

struct inode_perm_data {
	unsigned long matched;
};

static int perm_inode_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;
	struct inode *inode = (struct inode *)regs->regs[PM_PERM_INODE_REG];

	d->matched = should_hide_for_current() && is_target_inode(inode);
	return 0;
}

static int perm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;

	if (d->matched)
		regs_set_return_value(regs, -ENOENT);
	return 0;
}

static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;
	struct path *path = (struct path *)regs->regs[0];
	struct inode *inode = NULL;

	if (path && path->dentry)
		inode = d_inode(path->dentry);

	d->matched = should_hide_for_current() && is_target_inode(inode);
	return 0;
}

static int getattr_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;

	if (d->matched)
		regs_set_return_value(regs, -ENOENT);
	return 0;
}

static int register_perm_getattr(void)
{
	int ret;

	if (hook_perm && !perm_registered) {
		kp_inode_perm.kp.symbol_name = "inode_permission";
		kp_inode_perm.entry_handler = perm_inode_entry;
		kp_inode_perm.handler = perm_exit;
		kp_inode_perm.data_size = sizeof(struct inode_perm_data);
		kp_inode_perm.maxactive = 40;
		ret = register_kretprobe(&kp_inode_perm);
		if (ret) {
			pr_warn(PM_LOG_PREFIX
				"register_kretprobe(inode_permission) failed: %d\n",
				ret);
			return ret;
		}
		perm_registered = true;
		pr_info(PM_LOG_PREFIX "hooked inode_permission\n");
	}

	if (hook_getattr && !getattr_registered) {
		kp_inode_getattr.kp.symbol_name = "vfs_getattr";
		kp_inode_getattr.entry_handler = getattr_entry;
		kp_inode_getattr.handler = getattr_exit;
		kp_inode_getattr.data_size = sizeof(struct inode_perm_data);
		kp_inode_getattr.maxactive = 40;
		ret = register_kretprobe(&kp_inode_getattr);
		if (ret) {
			pr_warn(PM_LOG_PREFIX
				"register_kretprobe(vfs_getattr) failed: %d\n",
				ret);
			if (perm_registered) {
				unregister_kretprobe(&kp_inode_perm);
				perm_registered = false;
			}
			return ret;
		}
		getattr_registered = true;
		pr_info(PM_LOG_PREFIX "hooked vfs_getattr\n");
	}

	return 0;
}

/* --------------------------- getdents64 --------------------------- */

static struct kretprobe kp_getdents;
static bool getdents_registered;

struct getdents_cb_data {
	struct linux_dirent64 __user *dirent;
	void *kbuf;
	size_t kbuf_len;
	bool scoped;
};

static int getdents_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct getdents_cb_data *d = (struct getdents_cb_data *)ri->data;
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
	unsigned int count;

	d->dirent = NULL;
	d->kbuf = NULL;
	d->kbuf_len = 0;
	d->scoped = should_hide_for_current();

	if (!d->scoped || !user_regs)
		return 0;

	count = (unsigned int)user_regs->regs[2];
	d->dirent = (struct linux_dirent64 __user *)user_regs->regs[1];

	count = min(count, GETDENTS_BUF_LIMIT);
	if (!count)
		return 0;

	d->kbuf = kmalloc(count, GFP_ATOMIC);
	if (d->kbuf)
		d->kbuf_len = count;
	return 0;
}

static int getdents_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct getdents_cb_data *d = (struct getdents_cb_data *)ri->data;
	long ret = regs->regs[0];
	struct linux_dirent64 *kbuf, *prev, *cur;
	long bpos, new_len;
	const size_t hdr_off = offsetof(struct linux_dirent64, d_name);
	const size_t min_reclen = offsetof(struct linux_dirent64, d_name) + 1;
	bool modified = false;

	if (ret <= 0 || !d->scoped || !d->dirent || !d->kbuf)
		goto out;

	if ((size_t)ret > d->kbuf_len)
		goto out;

	if (copy_from_user(d->kbuf, d->dirent, ret))
		goto out;

	kbuf = d->kbuf;
	prev = NULL;
	bpos = 0;
	new_len = ret;

	while (bpos + (long)hdr_off < new_len) {
		unsigned short reclen;

		cur = (struct linux_dirent64 *)((char *)kbuf + bpos);
		reclen = cur->d_reclen;

		if (reclen < min_reclen || reclen > new_len - bpos)
			break;

		if (is_target_ino(cur->d_ino)) {
			modified = true;
			if (prev) {
				if ((unsigned int)prev->d_reclen + reclen <=
				    65535u) {
					prev->d_reclen += reclen;
					bpos += reclen;
					continue;
				}
			}

			new_len -= reclen;
			if (new_len > bpos)
				memmove(cur, (char *)cur + reclen,
					new_len - bpos);
			continue;
		}

		prev = cur;
		bpos += reclen;
	}

	if (modified) {
		if (copy_to_user(d->dirent, kbuf, new_len))
			pr_warn_ratelimited(PM_LOG_PREFIX
					    "copy_to_user failed, directory may leak\n");
		else
			regs->regs[0] = new_len;
	}

out:
	kfree(d->kbuf);
	d->kbuf = NULL;
	d->kbuf_len = 0;
	return 0;
}

static int register_getdents(void)
{
	int ret;

	if (!hook_getdents)
		return 0;
	if (getdents_registered)
		return 0;

	kp_getdents.kp.symbol_name = "__arm64_sys_getdents64";
	kp_getdents.entry_handler = getdents_entry;
	kp_getdents.handler = getdents_exit;
	kp_getdents.data_size = sizeof(struct getdents_cb_data);
	kp_getdents.maxactive = 20;
	ret = register_kretprobe(&kp_getdents);
	if (ret) {
		pr_warn(PM_LOG_PREFIX
			"register_kretprobe(__arm64_sys_getdents64) failed: %d\n",
			ret);
		return ret;
	}
	getdents_registered = true;
	pr_info(PM_LOG_PREFIX "hooked __arm64_sys_getdents64\n");
	return 0;
}

static void unregister_getdents(void)
{
	if (getdents_registered) {
		unregister_kretprobe(&kp_getdents);
		getdents_registered = false;
	}
}

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
		pr_info(PM_LOG_PREFIX "hooked %s\n", p->symbol);
	}
}

static void unregister_syscall_hooks(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(pm_syscall_probes); i++) {
		struct pm_syscall_probe *p = &pm_syscall_probes[i];

		if (p->registered) {
			unregister_kretprobe(&p->rp);
			p->registered = false;
		}
	}
}

/* --------------------------- target resolution --------------------------- */

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
	pr_info(PM_LOG_PREFIX "target[%u] %s ino=%llu dev=%u:%u\n",
		target_count, path_name, targets[target_count].ino,
		MAJOR(targets[target_count].dev),
		MINOR(targets[target_count].dev));
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
	if (!strcmp(scope_mode, "global")) {
		active_scope = SCOPE_GLOBAL;
		return 0;
	}
	if (!strcmp(scope_mode, "deny")) {
		active_scope = SCOPE_DENY;
		return 0;
	}
	if (!strcmp(scope_mode, "allow")) {
		active_scope = SCOPE_ALLOW;
		return 0;
	}

	pr_err(PM_LOG_PREFIX "unsupported scope_mode=%s\n", scope_mode);
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

/* --------------------------- apply / reload --------------------------- */

static void reset_state(void)
{
	target_count = 0;
	deny_uid_count = 0;
	allow_uid_count = 0;
}

static void unregister_all_hooks(void)
{
	if (perm_registered) {
		unregister_kretprobe(&kp_inode_perm);
		perm_registered = false;
	}
	if (getattr_registered) {
		unregister_kretprobe(&kp_inode_getattr);
		getattr_registered = false;
	}
	unregister_syscall_hooks();
	unregister_getdents();
}

static int apply_config(void)
{
	int ret;
	const char *paths = target_paths[0] ? target_paths : NULL;

	/* Run in process context (sysfs write). Rebuild state from scratch. */
	unregister_all_hooks();
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

	if (paths) {
		ret = resolve_target_paths(paths);
		if (ret)
			pr_warn(PM_LOG_PREFIX
				"resolve_target_paths: %d (targets=%u)\n",
				ret, target_count);
	}

	if (hook_perm || hook_getattr)
		register_perm_getattr();

	if (hide_dirents && hook_getdents)
		register_getdents();

	if (parse_syscall_hooks())
		register_syscall_hooks();

	pr_info(PM_LOG_PREFIX
		"applied -- targets=%u scope=%s deny_uids=%u allow_uids=%u "
		"hide_dirents=%d hooks=[perm=%d getattr=%d getdents=%d]\n",
		target_count, scope_mode, deny_uid_count, allow_uid_count,
		hide_dirents, hook_perm, hook_getattr,
		hook_getdents && hide_dirents);
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
module_param_cb(reload, &reload_ops, &reload_trigger, 0644);
MODULE_PARM_DESC(reload, "Write 1 to (re)apply configuration from sysfs");

static int pkgmask_status_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE,
		"targets=%u scope=%s deny_uids=%u allow_uids=%u "
		"hooks=[perm=%d getattr=%d getdents=%d syscall=%d]\n",
		target_count, scope_mode, deny_uid_count, allow_uid_count,
		perm_registered, getattr_registered, getdents_registered,
		pm_syscall_probes[0].registered);
}

static const struct kernel_param_ops status_ops = {
	.get = pkgmask_status_get,
};
static int status_dummy;
module_param_cb(status, &status_ops, &status_dummy, 0444);
MODULE_PARM_DESC(status, "Read-only state dump");

/* --------------------------- init --------------------------- */

static int __init pkgmask_init(void)
{
	/*
	 * Boot-time registration is deliberately minimal: the two
	 * pure-memory-read hooks with an empty target list are a no-op
	 * for every process. Real configuration arrives later through
	 * sysfs + reload, once /data is mounted.
	 */
	register_perm_getattr();

	pr_info(PM_LOG_PREFIX
		"built-in ready; configure via "
		"/sys/module/pkgmask/parameters/* then write 1 to reload\n");
	return 0;
}

module_init(pkgmask_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("a41929566");
MODULE_DESCRIPTION("Built-in kernel package hiding (zero-width safe)");
