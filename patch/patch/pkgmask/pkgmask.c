// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask v4.11 -- kernel-level app package / directory hiding
 *
 * Why built-in: the hiding entry point for readdir is a strong
 * definition of pmk_filter_dirent() that overrides the __weak default
 * in fs/readdir.c.  The linker resolves the weak reference to this
 * strong symbol only when both live in vmlinux (CONFIG_PKGMASK=y),
 * which is why this driver is built-in and not an LKM.
 *
 * v4.6 changes (stable):
 *   - v4.11: binder.c injection and syscall-fallback code are FULLY
 *     removed (no inert params, no sysfs exposure, no kallsyms entries).
 *     Only readdir weak-hook + inode_permission/vfs_getattr kretprobes
 *     remain, minimizing detection surface.  hwid_spoof (read-only HWID
 *     interception) is preserved and initialized here.
 *   - readdir hiding via filldir64/filldir weak hook (zero-width
 *     immune, matches by parent dir (dev,ino) + entry name).
 *   - stat / open hiding via inode_permission + vfs_getattr kretprobes.
 *   - v4.9: target_paths tokens are trimmed of trailing whitespace/newline
 *     so echo/printf writes both work (echo appends '\n').
 *   - v4.9: /proc process-name hiding (hide_proc_enabled + hide_proc_names);
 *     PID-string entries resolved to task->comm for matching.
 *     hide_dirents/hook_getdents default to 1 so SUSFS guard's
 *     pkgmask_setup.sh (which does not write them) still gets readdir hiding.
 *     compatible with SUSFS Env Guard's pkgmask integration.
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
#include <linux/fdtable.h>
#include <linux/version.h>
#include <linux/magic.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include "hwid_spoof.h"


#define PM_LOG_PREFIX "pkgmask: "
#define MAX_HIDE_TARGETS 64
#define TARGET_TEXT_LEN 512
#define TARGET_PATHS_LEN 4096
#define MAX_DENY_UIDS 128
#define MAX_ALLOW_UIDS 128
#define UID_LIST_LEN 1024

/* --------------------------- tunables --------------------------- */

static bool hide_dirents = true;
module_param(hide_dirents, bool, 0600);
MODULE_PARM_DESC(hide_dirents, "Master switch for dirent hiding");

static bool hook_getdents = true;
module_param(hook_getdents, bool, 0600);
MODULE_PARM_DESC(hook_getdents, "Enable filldir readdir filter");

static bool hook_perm;
module_param(hook_perm, bool, 0600);
MODULE_PARM_DESC(hook_perm, "Enable inode_permission hook");

static bool hook_getattr;
module_param(hook_getattr, bool, 0600);
MODULE_PARM_DESC(hook_getattr, "Enable vfs_getattr hook");


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


/* SUSFS guard compatible: /proc process-name hiding (v4.9) */
static bool hide_proc_enabled;
module_param(hide_proc_enabled, bool, 0600);
MODULE_PARM_DESC(hide_proc_enabled, "Hide /proc entries matching hide_proc_names (SUSFS guard)");

#define MAX_HIDE_PROC_NAMES 16
#define HIDE_PROC_NAMES_LEN 256
static char hide_proc_names_buf[HIDE_PROC_NAMES_LEN];
static char proc_names[MAX_HIDE_PROC_NAMES][TARGET_TEXT_LEN];
static unsigned int proc_name_count;
module_param_string(hide_proc_names, hide_proc_names_buf,
		    sizeof(hide_proc_names_buf), 0600);
MODULE_PARM_DESC(hide_proc_names, "Comma-separated process names to hide in /proc");

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
	/* v4.7: last path component as package-name prefix — hides
	 * /data/app/<rand>/<pkg>-<suffix> style entries whose random
	 * directory name cannot be pre-resolved. */
	char pkg[TARGET_TEXT_LEN];
	bool have_pkg;
};

static struct hidden_target targets[MAX_HIDE_TARGETS];
static unsigned int target_count;

static enum pkgmask_scope_mode active_scope = SCOPE_DENY;
static uid_t deny_uid_list[MAX_DENY_UIDS];
static unsigned int deny_uid_count;
static uid_t allow_uid_list[MAX_ALLOW_UIDS];
static unsigned int allow_uid_count;

/* --------------------------- helpers --------------------------- */

/*
 * v4.12: /proc/<pid>/comm direct-read defense.
 *
 * process_hide filters /proc root getdents by PID->comm, but a detector
 * that brute-forces /proc/1..N and reads /proc/<pid>/comm directly still
 * sees the hidden comm. This kretprobe intercepts vfs_read() on that path
 * and returns 0 (EOF) so the caller reads an empty file.
 */

static bool is_in_uid_list(const uid_t *list, unsigned int count, uid_t uid)
{
	unsigned int i;
	for (i = 0; i < count; i++)
		if (list[i] == uid)
			return true;
	return false;
}

/*
 * 向上追溯 depth 层 real_parent，检查祖先链上是否有 deny_uids 里的 UID
 * 场景：检测方 su 后，root shell 的祖先仍可追溯到检测方进程
 *
 * 只做 real_parent 追溯（不做 cgroup），原因是：
 *   1) cgroup 需要 task_cgroup_path() 拿 cgroup_mutex，可能在某些内核
 *      持锁路径里被调用导致死锁
 *   2) real_parent 追溯用 rcu_dereference，纯读操作，无死锁风险
 *   3) 能挡住"检测方直接 su"的场景，这也是绝大多数检测工具的手法
 */

static bool has_deny_ancestor(int depth)
{
	struct task_struct *task = current;
	int i;
	if (active_scope != SCOPE_DENY)
		return false;
	rcu_read_lock();
	for (i = 0; i < depth && task->real_parent; i++) {
		task = task->real_parent;
		if (task->pid == 1)
			break;
		{
			uid_t uid = from_kuid(&init_user_ns, task_uid(task));
			if (is_in_uid_list(deny_uid_list, deny_uid_count, uid)) {
				rcu_read_unlock();
				return true;
			}
		}
	}
	rcu_read_unlock();
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

	if (active_scope == SCOPE_DENY) {
		/* 快路径：直接命中 deny_uids（普通 APP 走这里，零开销） */
		if (is_in_uid_list(deny_uid_list, deny_uid_count, uid))
			return true;

		/* 慢路径：仅在 hook_perm/hook_getattr 开启时才追溯祖先，层数 3 */
		if (hook_perm || hook_getattr) {
			if (has_deny_ancestor(3))
				return true;
		}
		return false;
	}

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
 *
 * v4.7: in addition to the exact parent+name match, an entry whose
 * name starts with the configured package name (followed by a name
 * separator / alnum) is hidden everywhere.  This covers Android
 * install dirs like /data/app/~~x==/<pkg>-<random> whose random
 * directory cannot be known ahead of time.
 */
bool iterate_dir_filter(const char *name, const struct inode *dir)
{
	unsigned int i;
	size_t plen;

	if (!hide_dirents || !hook_getdents || !dir || !name)
		return false;
	if (!should_hide_for_current())
		return false;

	/* /proc process-name hiding:
	 * name is the PID string (e.g. "1234"), not the process name.
	 * Resolve PID -> task_struct->comm and compare against the list.
	 * Only apply at the /proc root (i_ino == 1). kstrtoint avoids a
	 * long->int truncation hazard in 64-bit builds.
	 */
	if (hide_proc_enabled && proc_name_count &&
	    dir->i_sb && dir->i_sb->s_magic == PROC_SUPER_MAGIC &&
	    dir->i_ino == 1) {
		int lpid;
		pid_t pid;

		if (kstrtoint(name, 10, &lpid) == 0 && lpid > 0) {
			struct task_struct *task;
			unsigned int j;

			pid = (pid_t)lpid;
			rcu_read_lock();
			task = find_task_by_vpid(pid);
			if (task) {
				for (j = 0; j < proc_name_count; j++) {
					if (strcmp(task->comm, proc_names[j]) == 0) {
						rcu_read_unlock();
						return true;
					}
				}
			}
			rcu_read_unlock();
		}
	}

	if (!target_count)
		return false;

	for (i = 0; i < target_count; i++) {
		if (targets[i].parent_ok &&
		    dir->i_ino == targets[i].parent_ino &&
		    dir->i_sb && dir->i_sb->s_dev == targets[i].parent_dev &&
		    strcmp(name, targets[i].name) == 0)
			return true;

		if (targets[i].have_pkg) {
			char c;

			plen = strlen(targets[i].pkg);
			if (plen && strncmp(name, targets[i].pkg, plen) == 0) {
				c = name[plen];
				if (c == '\0' || c == '-' || c == '_' || c == '.' ||
				    (c >= '0' && c <= '9') ||
				    (c >= 'a' && c <= 'z') ||
				    (c >= 'A' && c <= 'Z'))
					return true;
			}
		}
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

static int perm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode *inode;

	if (!hide_dirents || !hook_perm || !target_count)
		return 0;
	if (!should_hide_for_current())
		return 0;
	inode = *(struct inode **)ri->data;
	if (is_target_inode(inode))
		regs->regs[0] = -ENOENT;
	return 0;
}

static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!hide_dirents || !hook_getattr || !target_count)
		return 0;
	*(struct path **)ri->data = (struct path *)regs->regs[0];
	return 0;
}

static int getattr_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path *path;

	if (!hide_dirents || !hook_getattr || !target_count)
		return 0;
	if (!should_hide_for_current())
		return 0;
	path = *(struct path **)ri->data;
	if (path && path->dentry && path->dentry->d_inode &&
	    is_target_inode(path->dentry->d_inode))
		regs->regs[0] = -ENOENT;
	return 0;
}
/* v4.13: /proc/<pid>/comm direct-read defense (lazy, maxactive=32) */
static struct kretprobe proc_comm_kp;
static bool proc_comm_hook_active;

static int proc_comm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct file *file;
    struct dentry *dentry;
    const char *name;

    if (!hide_proc_enabled || !proc_name_count)
        return 0;

    /* UID 快筛：只对 deny_uids 生效，避免无关进程开销 */
    if (active_scope == SCOPE_DENY) {
        uid_t uid = from_kuid(&init_user_ns, current_uid());
        if (!is_in_uid_list(deny_uid_list, deny_uid_count, uid))
            return 0;
    }

    file = (struct file *)regs->regs[0];
    if (!file) return 0;
    dentry = file->f_path.dentry;
    if (!dentry) return 0;

    name = dentry->d_name.name;
    if (strcmp(name, "comm") != 0) return 0;

    /* 父目录名必须是 PID 数字 */
    if (dentry->d_parent) {
        const char *pname = dentry->d_parent->d_name.name;
        if (pname[0] >= '1' && pname[0] <= '9') {
            *(struct dentry **)ri->data = dentry;
            return 0;
        }
    }
    return 0;
}

static int proc_comm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dentry *dentry = *(struct dentry **)ri->data;
    struct task_struct *task;
    int lpid;
    unsigned int j;

    if (!dentry) return 0;

    if (kstrtoint(dentry->d_parent->d_name.name, 10, &lpid) != 0 || lpid <= 0)
        return 0;

    rcu_read_lock();
    task = find_task_by_vpid(lpid);
    if (task) {
        for (j = 0; j < proc_name_count; j++) {
            if (strcmp(task->comm, proc_names[j]) == 0) {
                rcu_read_unlock();
                /* 隐藏：返回 0 (EOF) */
                regs->regs[0] = 0;
                return 0;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

static void register_proc_comm_hook(void)
{
    int ret;
    if (proc_comm_hook_active) return;
    memset(&proc_comm_kp, 0, sizeof(proc_comm_kp));
    proc_comm_kp.kp.symbol_name = "vfs_read";
    proc_comm_kp.entry_handler = proc_comm_entry;
    proc_comm_kp.handler = proc_comm_exit;
    proc_comm_kp.data_size = sizeof(void *);
    proc_comm_kp.maxactive = 32;
    ret = register_kretprobe(&proc_comm_kp);
    if (ret < 0) {
        pr_info(PM_LOG_PREFIX "vfs_read (comm) probe unavailable (%d)\n", ret);
        memset(&proc_comm_kp, 0, sizeof(proc_comm_kp));
        return;
    }
    proc_comm_hook_active = true;
}

static void unregister_proc_comm_hook(void)
{
    if (proc_comm_hook_active)
        unregister_kretprobe(&proc_comm_kp);
    proc_comm_hook_active = false;
    memset(&proc_comm_kp, 0, sizeof(proc_comm_kp));
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


/* --------------------------- target resolution --------------------------- */

static void set_target_pkg(struct hidden_target *t, const char *path_str)
{
	const char *slash = strrchr(path_str, '/');

	if (slash && slash[1]) {
		strscpy(t->pkg, slash + 1, sizeof(t->pkg));
		t->have_pkg = true;
	}
}

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
	set_target_pkg(&targets[target_count], path_str);

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
			set_target_pkg(&targets[target_count], alias);
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
			set_target_pkg(&targets[target_count], alias);
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
		/* v4.9: strip trailing whitespace/newline (echo writes '\n') */
		{
			size_t tl = strlen(tok);
			while (tl > 0 && (tok[tl - 1] == '\n' || tok[tl - 1] == '\r' ||
					  tok[tl - 1] == ' ' || tok[tl - 1] == '\t'))
				tok[--tl] = '\0';
		}
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

static void trim_param(char *s)
{
	size_t l = strlen(s);

	while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r' ||
			  s[l - 1] == ' ' || s[l - 1] == '\t'))
		s[--l] = '\0';
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

static void parse_hide_proc_names(const char *buf)
{
	char tmp[HIDE_PROC_NAMES_LEN];
	char *tok;
	char *comma;

	proc_name_count = 0;
	strscpy(tmp, buf, sizeof(tmp));
	tok = tmp;
	while (tok && *tok && proc_name_count < MAX_HIDE_PROC_NAMES) {
		comma = strchr(tok, ',');
		if (comma)
			*comma = '\0';
		tok = tok + strspn(tok, " \t");
		if (*tok) {
			size_t tl = strlen(tok);
			while (tl > 0 && (tok[tl - 1] == '\n' || tok[tl - 1] == '\r' ||
					  tok[tl - 1] == ' ' || tok[tl - 1] == '\t'))
				tok[--tl] = '\0';
			if (*tok) {
				strscpy(proc_names[proc_name_count], tok,
					sizeof(proc_names[0]));
				proc_name_count++;
			}
		}
		tok = comma ? comma + 1 : NULL;
	}
}

static void unregister_all_hooks(void)
{
    unregister_perm_getattr_hooks();
    unregister_proc_comm_hook();
}

static int apply_config(void)
{
	/* echo writes '\n'; trim all string params before parsing */
	trim_param(scope_mode);
	trim_param(deny_uids);
	trim_param(allow_uids);
	trim_param(target_paths);
	trim_param(hide_proc_names_buf);

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
	parse_hide_proc_names(hide_proc_names_buf);

	if (hook_perm || hook_getattr)
		register_perm_getattr_hooks();
	
	if (hide_proc_enabled && proc_name_count)
        register_proc_comm_hook();
    else
        unregister_proc_comm_hook();

	pr_debug(PM_LOG_PREFIX "config applied: scope=%s targets=%u deny=%u allow=%u "
		"dirents=%d getdents=%d perm=%d getattr=%d prochide=%d proccount=%u\n",
		scope_mode, target_count, deny_uid_count, allow_uid_count,
		hide_dirents ? 1 : 0, hook_getdents ? 1 : 0,
		hook_perm ? 1 : 0, hook_getattr ? 1 : 0,
		hide_proc_enabled ? 1 : 0, proc_name_count);
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
	/* 安全：不暴露模块版本号和具体 hook 清单
	 * 旧版输出 "pkgmask v4.11" 版本号 + hook_perm/hook_getattr 等开关
	 * 检测方可按字符串匹配识别模块，或根据 hook 清单判断隐藏能力
	 * 新版只保留"是否工作"的最基本信息 */
	return scnprintf(buffer, PAGE_SIZE,
			 "scope=%s targets=%u\n"
			 "enabled=%d\n",
			 scope_mode, target_count,
			 hide_dirents ? 1 : 0);
}

static struct kernel_param_ops status_ops = {
	.get = status_get,
};
module_param_cb(status, &status_ops, NULL, 0400);

/* --------------------------- init --------------------------- */

static int __init xk7a9f_init(void)
{
	/*
	 * v4.14: 启动时不注册任何 kretprobe。
	 *
	 * inode_permission / vfs_getattr 是 VFS 最热的函数，每次文件访问
	 * 都会经过。在开机早期无条件挂 kretprobe，会让 init 阶段的权限
	 * 检查 / stat 调用多两次陷入（保存 pt_regs、return address
	 * trampoline、entry/exit handler），足以把一加 Bootloader 的启动
	 * 时间窗口拖破 → 判启动失败 → 卡黄字无限重启。
	 *
	 * v4.13 已经处理了 vfs_read 的惰性化，但 inode_permission /
	 * vfs_getattr 这两个更热的 kretprobe 仍然在 init 里无条件注册。
	 * v4.14 一并惰性化：只有用户态通过 sysfs 写入 hook_perm=1 或
	 * hook_getattr=1 并触发 reload，apply_config() 才按需注册。
	 *
	 * SUSFS Env Guard 的 pkgmask_setup.sh 会在 sys.boot_completed==1
	 * 之后写 hook_perm=1 / hook_getattr=1 并触发 reload，功能不受影响，
	 * 只是延后到系统稳定之后注册。
	 */
#ifdef CONFIG_PKGMASK_HWID
	xw3e8b_init();
#endif

	pr_debug(PM_LOG_PREFIX "v4.14 built-in initialized (deferred kretprobe registration)\n");
	return 0;
}

static void __exit xk7a9f_exit(void)
{
#ifdef CONFIG_PKGMASK_HWID
	xw3e8b_exit();
#endif
	reset_state();
	pr_debug(PM_LOG_PREFIX "unloaded\n");
}

module_init(xk7a9f_init);
module_exit(xk7a9f_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pkgmask");
MODULE_DESCRIPTION("pkgmask v4.11 kernel-level package hiding (built-in)");
