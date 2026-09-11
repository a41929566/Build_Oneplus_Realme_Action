// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask - built-in kernel package hiding for Android arm64 / GKI 6.6
 *
 * Built into the kernel image (obj-y), NOT a loadable module.
 *
 * Mechanism (v3):
 *   1. getdents64 kretprobe   - directory entry filtering (scan-proof listing)
 *   2. LSM hooks              - inode_permission / inode_getattr deny
 *                               (stat / open / access -> ENOENT)
 *   3. __arm64_sys_* path kretprobes as fallback (optional, off by default)
 *
 * v3 change: kretprobes on inode_permission / vfs_getattr are removed.
 * On kernels where SUSFS (or similar) permanently ftrace-hooks those VFS
 * functions, register_kretprobe returns -EINVAL and the hide never engages.
 * LSM hooks use an independent hook chain and keep working in that setup.
 *
 * v3.1: adapt to the vendor (OnePlus SM8750) LSM API:
 *   - inode_getattr hook takes a single `const struct path *` (no idmap)
 *   - security_add_hooks(hooks, count, "name") legacy signature (no lsm_id)
 *
 * getdents64 / syscall kretprobes are registered at most once and never
 * unregistered: reload only refreshes the match data.  Handlers consult the
 * live config on every call, so re-applying config never touches kprobe
 * registration (avoids -EINVAL/-EEXIST on re-registration).
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
MODULE_PARM_DESC(hook_perm, "Enable inode_permission LSM hook");

static bool hook_getattr = true;
module_param(hook_getattr, bool, 0644);
MODULE_PARM_DESC(hook_getattr, "Enable inode_getattr LSM hook");

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
			