// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask v4.6 -- kernel-level app package / directory hiding
 *
 * Why built-in: the hiding entry point for readdir is a strong
 * definition of pmk_filter_dirent() that overrides the __weak default
 * in fs/readdir.c.  The linker resolves the weak reference to this
 * strong symbol only when both live in vmlinux (CONFIG_PKGMASK=y),
 * which is why this driver is built-in and not an LKM.
 *
 * v4.6 changes (stable):
 *   - binder.c injection is DISABLED by default (BINDER_INJECT=False
 *     in the workflow, binder_enabled=0 here).  Binder filter code is
 *     kept only as inert parameters so the WebUI keeps working; no
 *     binder_transaction code path is touched, no crash surface.
 *   - readdir hiding via filldir64/filldir weak hook (zero-width
 *     immune, matches by parent dir (dev,ino) + entry name).
 *   - stat / open hiding via inode_permission + vfs_getattr kretprobes.
 *
 * Runtime configuration (live, no reboot):
 *   /sys/module/pkgmask/parameters/target_paths   e.g.
 *     /data/user/0/com.maple.detect,/data/user/0/bin.mt.plus.canary
 *   /sys/module/pkgmask/parameters/deny_uids      e.g. 10354
 *   /sys/module/pkgmask/parameters/allow_uids
 *   /sys/module/pkgmask/parameters/scope_mode     global|deny|allow
 *   /sys/module/pkgmask/parameters/hide_dirents   1|0
 *   /sys/module/pkgmask/parameters/hook_getdents  1|0 (readdir filter)
 *   /sys/module/pkgmask/parameters/hook_perm      1|0
 *   /sys/module/pkgmask/parameters/hook_getattr   1|0
 *   /sys/module/pkgmask/parameters/reload         write "1" to apply
 *   /sys/module/pkgmask/parameters/status         read-only
 *
 * At boot only no-op hooks are registered (empty target list); nothing
 * is hidden until configuration is applied via sysfs.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/statfs.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

extern int close_fd(unsigned int fd);

#define PM_LOG_PREFIX "pkgmask: "
#define MAX_HIDE_TARGETS 64
#define TARGET_TEXT_LEN 512
#define TARGET_PATHS_LEN 4096
#define MAX_DENY_UIDS 128
#define MAX_ALLOW_UIDS 128
#define UID_LIST_LEN 1024
#define PM_SYSCALL_HOOKS_LEN 512

/* --------------------------- tunables --------------------------- */

static bool hide_dirents = true;
module_param(hide_dirents, bool, 0600);
MODULE_PARM_DESC(hide_dirents, "Master switch for dirent hiding");

static bool hook_getdents;
module_param(hook_getdents, bool, 0600);
MODULE_PARM_DESC(hook_getdents, "Enable filldir readdir filter");

static bool hook_perm;
module_param(hook_perm, bool, 0600);
MODULE_PARM_DESC(hook_perm, "Enable inode_permission hook");

static bool hook_getattr;
module_param(hook_getattr, bool, 0600);
MODULE_PARM_DESC(hook_getattr, "Enable vfs_getattr hook");

static bool enable_syscall_hooks;
module_param(enable_syscall_hooks, bool, 0600);
MODULE_PARM_DESC(enable_syscall_hooks, "Enable syscall fallback hooks (off by default)");

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

/* Binder params kept for WebUI compatibility (v4.6: inert, no binder.c hook) */
static char binder_hide_packages[1024];
module_param_string(binder_hide_packages, binder_hide_packages,
		    sizeof(binder_hide_packages), 0600);
MODULE_PARM_DESC(binder_hide_packages,
		 "Comma-separated package names (reserved, inert in v4.6)");

static bool binder_enabled;
module_param(binder_enabled, bool, 0600);
MODULE_PARM_DESC(binder_enabled, "Binder scrubbing master toggle (reserved, off)");

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
	/* v3.2+: parent directory (dev, ino) + entry name for readdir filter */
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
static uid_t allow_uid_list[MAX_ALLOW_UIDS];
static unsigned int allow_uid_count;

/* --------------------------- helpers --------------------------- */

static bool is_in_uid_list(const uid_t *list, unsigned int count, uid_t uid)
{
	unsigned int i;
	for (i = 0; i < count; i++)
		if (list[i] == uid)
			return true;
	return false;
}

static bool should_hide_for_current(void)
{
	uid_t uid;
	kuid_t kuid;

	if (active_scope == SCOPE_GLOBAL)
		return true;

	kuid = current_uid();
	uid = from_kuid(&init_user_ns, kuid);

	if (active_scope == SCOPE_DENY)
		return is_in_uid_list(deny_uid_list, deny_uid_count, uid);
	if (active_scope == SCOPE_ALLOW)
		return !is_in_uid_list(allow_uid_list, allow_uid_count, uid);
	return false;
}

static bool is_target_inode(const struct inode *inode)
{
	unsigned int i;
	if (!inode || !target_count)
		return false;
	for (i = 0; i < target_count; i++) {
		if (!targets[i].inode_ok)
			continue;
		if (inode->i_ino == targets[i].ino &&
		    inode->i_sb && inode->i_sb->s_dev == targets[i].dev)
			return true;
	}
	return false;
}

/*
 * Strong definition of the fs/readdir.c weak hook.  Called from
 * filldir64/filldir with (entry name, parent dir inode).  Returning
 * true skips the entry without writing it, so the listing stays
 * compact and offsets stay valid.  Zero-width immune: the check is by
 * parent (dev, ino) + exact entry name, never by string walking.
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
		    dir->i_sb && dir->i_sb->s_dev == targets[i].parent_dev &&
		    strcmp(name, targets[i].name) == 0)
			return true;
	}
	return false;
}

/* --------------------------- perm/getattr kretprobes --------------------------- */

static struct kretprobe perm_kp;
static struct kretprobe getattr_kp;

/*
 * Safe pattern: entry stores the target pointer into ri->data; exit
 * rewrites only the return value (-ENOENT) for matching inodes.  We
 * never touch argument registers, so no crash surface inside the
 * probed function.
 *
 * inode_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
 *   -> inode is regs[1] on arm64.
 * vfs_getattr(const struct path *path, ...)
 *   -> path is regs[0] on arm64.
 */
static int perm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!hide_dirents || !hook_perm || !target_count)
		return 0;
	*(struct inode **)ri->data = (struct inode *)regs->regs[1];
	return 0;
}

static void perm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode *inode;

	if (!hide_dirents || !hook_perm || !target_count)
		return;
	inode = *(struct inode **)ri->data;
	if (is_target_inode(inode))
		regs_return_value(regs) = -ENOENT;
}

static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!hide_dirents || !hook_getattr || !target_count)
		return 0;
	*(struct path **)ri->data = (struct path *)regs->regs[0];
	return 0;
}

static void getattr_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path *path;

	if (!hide_dirents || !hook_getattr || !target_count)
		return;
	path = *(struct path **)ri->data;
	if (path && path->dentry && path->dentry->d_inode &&
	    is_target_inode(path->dentry->d_inode))
		regs_return_value(regs) = -ENOENT;
}

static int register_perm_getattr_hooks(void)
{
	int ret;

	memset(&perm_kp, 0, sizeof(perm_kp));
	perm_kp.handler = perm_exit;
	perm_kp.entry_handler = perm_entry;
	perm_kp.data_size = sizeof(void *);
	perm_kp.maxactive = 64;
	perm_kp.kp.symbol_name = "inode_permission";
	ret = register_kretprobe(&perm_kp);
	if (ret < 0) {
		pr_info(PM_LOG_PREFIX "inode_permission hook unavailable (%d)\n", ret);
		memset(&perm_kp, 0, sizeof(perm_kp));
	}

	memset(&getattr_kp, 0, sizeof(getattr_kp));
	getattr_kp.handler = getattr_exit;
	getattr_kp.entry_handler = getattr_entry;
	getattr_kp.data_size = sizeof(void *);
	getattr_kp.maxactive = 64;
	getattr_kp.kp.symbol_name = "vfs_getattr";
	ret = register_kretprobe(&getattr_kp);
	if (ret < 0) {
		pr_info(PM_LOG_PREFIX "vfs_getattr hook unavailable (%d)\n", ret);
		memset(&getattr_kp, 0, sizeof(getattr_kp));
	}
	return 0;
}

static void unregister_perm_getattr_hooks(void)
{
	if (perm_kp.kp.symbol_name)
		unregister_kretprobe(&perm_kp);
	if (getattr_kp.kp.symbol_name)
		unregister_kretprobe(&getattr_kp);
	memset(&perm_kp, 0, sizeof(perm_kp));
	memset(&getattr_kp, 0, sizeof(getattr_kp));
}

/* --------------------------- syscall fallback (removed in v4.6) --------------------------- */
/*
 * v4.6: syscall fallback hooks are intentionally NOT registered.
 * The params enable_syscall_hooks / syscall_hooks are kept only so the
 * WebUI keeps writing them without error; they control nothing.
 */

/* --------------------------- target resolution --------------------------- */

static int add_target_path(const char *path_str)
{
	struct path path;
	struct inode *inode;
	struct inode *pinode;
	int ret;

	if (target_count >= MAX_HIDE_TARGETS)
		return -ENOSPC;

	ret = kern_path(path_str, 0, &path);
	if (ret) {
		pr_info(PM_LOG_PREFIX "path not resolvable: %s\n", path_str);
		return ret;
	}
	inode = d_inode(path.dentry);
	if (!inode) {
		path_put(&path);
		return -ENOENT;
	}

	targets[target_count].dev = inode->i_sb->s_dev;
	targets[target_count].ino = inode->i_ino;
	targets[target_count].inode_ok = inode->i_ino != 0;
	strscpy(targets[target_count].path, path_str,
		sizeof(targets[target_count].path));

	/* parent dir (dev, ino) + entry name for the readdir filter */
	if (path.dentry->d_parent) {
		pinode = d_inode(path.dentry->d_parent);
		if (pinode && pinode->i_sb) {
			targets[target_count].parent_ino = pinode->i_ino;
			targets[target_count].parent_dev = pinode->i_sb->s_dev;
			targets[target_count].parent_ok = pinode->i_ino != 0;
			strscpy(targets[target_count].name,
				(const char *)path.dentry->d_name.name,
				sizeof(targets[target_count].name));
		}
	}

	path_put(&path);

	/* alias spellings: /data/data/X -> /data/user/0/X and back */
	if (strncmp(path_str, "/data/data/", 11) == 0) {
		char alias[TARGET_TEXT_LEN];
		snprintf(alias, sizeof(alias), "/data/user/0/%s",
			 path_str + 11);
		if (target_count + 1 < MAX_HIDE_TARGETS &&
		    kern_path(alias, 0, &path) == 0) {
			inode = d_inode(path.dentry);
			if (inode) {
				target_count++;
				targets[target_count].dev = inode->i_sb->s_dev;
				targets[target_count].ino = inode->i_ino;
				targets[target_count].inode_ok = inode->i_ino != 0;
				strscpy(targets[target_count].path, alias,
					sizeof(targets[target_count].path));
				if (path.dentry->d_parent) {
					pinode = d_inode(path.dentry->d_parent);
					if (pinode && pinode->i_sb) {
						targets[target_count].parent_ino = pinode->i_ino;
						targets[target_count].parent_dev = pinode->i_sb->s_dev;
						targets[target_count].parent_ok = pinode->i_ino != 0;
						strscpy(targets[target_count].name,
							(const char *)path.dentry->d_name.name,
							sizeof(targets[target_count].name));
					}
				}
			}
			path_put(&path);
		}
	} else if (strncmp(path_str, "/data/user/0/", 13) == 0) {
		char alias[TARGET_TEXT_LEN];
		snprintf(alias, sizeof(alias), "/data/data/%s",
			 path_str + 13);
		if (target_count + 1 < MAX_HIDE_TARGETS &&
		    kern_path(alias, 0, &path) == 0) {
			inode = d_inode(path.dentry);
			if (inode) {
				target_count++;
				targets[target_count].dev = inode->i_sb->s_dev;
				targets[target_count].ino = inode->i_ino;
				targets[target_count].inode_ok = inode->i_ino != 0;
				strscpy(targets[target_count].path, alias,
					sizeof(targets[target_count].path));
				if (path.dentry->d_parent) {
					pinode = d_inode(path.dentry->d_parent);
					if (pinode && pinode->i_sb) {
						targets[target_count].parent_ino = pinode->i_ino;
						targets[target_count].parent_dev = pinode->i_sb->s_dev;
						targets[target_count].parent_ok = pinode->i_ino != 0;
						strscpy(targets[target_count].name,
							(const char *)path.dentry->d_name.name,
							sizeof(targets[target_count].name));
					}
				}
			}
			path_put(&path);
		}
	}

	target_count++;
	return 0;
}

static int resolve_target_paths(const char *buf)
{
	char tmp[TARGET_PATHS_LEN];
	char *tok;
	char *comma;
	int added = 0;
	int ret = 0;

	target_count = 0;
	memset(targets, 0, sizeof(targets));

	strscpy(tmp, buf, sizeof(tmp));
	tok = tmp;
	while (tok && *tok) {
		comma = strchr(tok, ',');
		if (comma)
			*comma = '\0';
		tok = tok + strspn(tok, " \t");
		if (*tok) {
			ret = add_target_path(tok);
			if (ret == 0)
				added++;
		}
		tok = comma ? comma + 1 : NULL;
	}
	return added ? 0 : ret;
}

/* --------------------------- config parsing --------------------------- */

static int parse_scope_mode(const char *buf)
{
	if (strcmp(buf, "global") == 0)
		active_scope = SCOPE_GLOBAL;
	else if (strcmp(buf, "allow") == 0)
		active_scope = SCOPE_ALLOW;
	else if (strcmp(buf, "deny") == 0)
		active_scope = SCOPE_DENY;
	else
		return -EINVAL;
	return 0;
}

static int add_uid_to_list(uid_t *list, unsigned int *count, unsigned int max,
			   uid_t uid)
{
	if (*count >= max)
		return -ENOSPC;
	list[(*count)++] = uid;
	return 0;
}

static int parse_uid_list(const char *buf, uid_t *list, unsigned int *count,
			  unsigned int max)
{
	char tmp[UID_LIST_LEN];
	char *tok;
	char *comma;
	uid_t uid;
	int ret = 0;

	*count = 0;
	strscpy(tmp, buf, sizeof(tmp));
	tok = tmp;
	while (tok && *tok) {
		comma = strchr(tok, ',');
		if (comma)
			*comma = '\0';
		tok = tok + strspn(tok, " \t");
		if (*tok) {
			if (kstrtouint(tok, 10, (unsigned int *)&uid))
				ret = -EINVAL;
			else
				ret = add_uid_to_list(list, count, max, uid);
			if (ret)
				break;
		}
		tok = comma ? comma + 1 : NULL;
	}
	return ret;
}

static void unregister_all_hooks(void)
{
	unregister_perm_getattr_hooks();
}

static int apply_config(void)
{
	unregister_all_hooks();

	target_count = 0;
	memset(targets, 0, sizeof(targets));

	if (parse_scope_mode(scope_mode)) {
		pr_info(PM_LOG_PREFIX "invalid scope_mode: %s\n", scope_mode);
		return -EINVAL;
	}
	if (parse_uid_list(deny_uids, deny_uid_list, &deny_uid_count,
			   MAX_DENY_UIDS)) {
		pr_info(PM_LOG_PREFIX "invalid deny_uids\n");
		return -EINVAL;
	}
	if (parse_uid_list(allow_uids, allow_uid_list, &allow_uid_count,
			   MAX_ALLOW_UIDS)) {
		pr_info(PM_LOG_PREFIX "invalid allow_uids\n");
		return -EINVAL;
	}
	resolve_target_paths(target_paths);

	if (hook_perm || hook_getattr)
		register_perm_getattr_hooks();

	pr_info(PM_LOG_PREFIX "config applied: scope=%s targets=%u deny=%u allow=%u "
		"dirents=%d getdents=%d perm=%d getattr=%d\n",
		scope_mode, target_count, deny_uid_count, allow_uid_count,
		hide_dirents ? 1 : 0, hook_getdents ? 1 : 0,
		hook_perm ? 1 : 0, hook_getattr ? 1 : 0);
	return 0;
}

static void reset_state(void)
{
	unregister_all_hooks();
	target_count = 0;
	deny_uid_count = 0;
	allow_uid_count = 0;
	memset(targets, 0, sizeof(targets));
	active_scope = SCOPE_DENY;
}

/* --------------------------- sysfs reload / status --------------------------- */

static int reload_store(const char *buf, const struct kernel_param *kp)
{
	if (buf[0] == '1')
		return apply_config();
	return -EINVAL;
}

static struct kernel_param_ops reload_ops = {
	.set = reload_store,
};
module_param_cb(reload, &reload_ops, NULL, 0600);

static int status_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE,
			 "pkgmask v4.6\n"
			 "scope=%s targets=%u deny=%u allow=%u\n"
			 "hide_dirents=%d hook_getdents=%d hook_perm=%d hook_getattr=%d\n"
			 "syscall_hooks=%d binder_enabled=%d (inert)\n",
			 scope_mode, target_count, deny_uid_count, allow_uid_count,
			 hide_dirents ? 1 : 0, hook_getdents ? 1 : 0,
			 hook_perm ? 1 : 0, hook_getattr ? 1 : 0,
			 enable_syscall_hooks ? 1 : 0, binder_enabled ? 1 : 0);
}

static struct kernel_param_ops status_ops = {
	.get = status_get,
};
module_param_cb(status, &status_ops, NULL, 0400);

/* --------------------------- init --------------------------- */

static int __init pkgmask_init(void)
{
	int ret;

	ret = register_perm_getattr_hooks();
	if (ret)
		pr_info(PM_LOG_PREFIX "initial perm/getattr hooks skipped (%d)\n", ret);

	pr_info(PM_LOG_PREFIX "v4.6 built-in initialized (nothing hidden until configured)\n");
	return 0;
}

static void __exit pkgmask_exit(void)
{
	reset_state();
	pr_info(PM_LOG_PREFIX "unloaded\n");
}

module_init(pkgmask_init);
module_exit(pkgmask_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pkgmask");
MODULE_DESCRIPTION("pkgmask v4.6 kernel-level package hiding (built-in)");
