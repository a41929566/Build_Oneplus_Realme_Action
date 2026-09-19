// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask v5.0
 *   - kernel-level app package / directory hiding (v4.15 functionality)
 *   - root-context stealth process hiding (C+B, v5 final)
 *
 * v5 additions:
 *   - hide_proc_names entries prefixed with '!' = stealth list:
 *     hidden from ALL readers including uid 0.
 *   - proc_comm_entry: removed hard uid gate; two-stage early-return.
 *   - proc_comm_exit: three branches (stealth / self-exemption / scoped).
 *   - iterate_dir_filter: stealth bypasses uid gate (global gate moved after
 *     the stealth proc block; scoped match still gated by should_hide).
 *   - perm/getattr: intercept /proc/<pid> directory lookup for stealth.
 *   - B-layer (perm/getattr) gated by PKGMASK_ENABLE_B_LAYER.
 *
 * All prior v4.15 functionality preserved.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/statfs.h>
#include <linux/version.h>
#include <linux/magic.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include "hwid_spoof.h"
/* B 层需要 fs/proc/internal.h；编译不过时把这个 #define 改成 0
 * 只保留 A 层（readdir）+ C 层（per-pid read） */
#define PKGMASK_ENABLE_B_LAYER 0
#ifdef PKGMASK_ENABLE_B_LAYER
#include "../../../fs/proc/internal.h"
#endif
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
static bool hide_proc_enabled;
module_param(hide_proc_enabled, bool, 0600);
MODULE_PARM_DESC(hide_proc_enabled, "Hide /proc entries matching hide_proc_names");
#define MAX_HIDE_PROC_NAMES 16
#define HIDE_PROC_NAMES_LEN 1024
static char hide_proc_names_buf[HIDE_PROC_NAMES_LEN];
static char proc_names[MAX_HIDE_PROC_NAMES][TARGET_TEXT_LEN];
static unsigned int proc_name_count;
/* v5: stealth list (prefix '!'), hidden from all readers incl. uid 0 */
static char stealth_names[MAX_HIDE_PROC_NAMES][TARGET_TEXT_LEN];
static unsigned int stealth_count;
module_param_string(hide_proc_names, hide_proc_names_buf,
		    sizeof(hide_proc_names_buf), 0600);
MODULE_PARM_DESC(hide_proc_names, "Comma-separated process names to hide in /proc; '!' prefix = stealth (any reader)");
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
	dev_t parent_dev;
	unsigned long long parent_ino;
	char name[TARGET_TEXT_LEN];
	bool parent_ok;
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
static bool is_in_uid_list(const uid_t *list, unsigned int count, uid_t uid)
{
	unsigned int i;
	for (i = 0; i < count; i++)
		if (list[i] == uid)
			return true;
	return false;
}
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
		if (is_in_uid_list(deny_uid_list, deny_uid_count, uid))
			return true;
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
/* ---------- v5 stealth helpers ---------- */
static bool reader_is_stealth(void)
{
	unsigned int i;
	for (i = 0; i < stealth_count; i++)
		if (strcmp(current->comm, stealth_names[i]) == 0)
			return true;
	return false;
}
static bool is_stealth_comm(const char *c)
{
	unsigned int i;
	if (!c)
		return false;
	for (i = 0; i < stealth_count; i++)
		if (strcmp(c, stealth_names[i]) == 0)
			return true;
	return false;
}
static bool is_scoped_comm(const char *c)
{
	unsigned int i;
	if (!c)
		return false;
	for (i = 0; i < proc_name_count; i++)
		if (strcmp(c, proc_names[i]) == 0)
			return true;
	return false;
}
/* dentry-based pid lookup: covers /proc/<pid>, /proc/<pid>/fd,
 * /proc/<pid>/task/<tid>. No internal.h dependency. */
static struct task_struct *pid_task_from_dentry(const struct dentry *d)
{
	struct task_struct *t = NULL;
	rcu_read_lock();
	while (d && d->d_parent) {
		const char *n = d->d_name.name;
		const struct dentry *p = d->d_parent;
		if (n && d->d_name.len >= 1 && d->d_name.len <= 11 &&
		    n[0] >= '1' && n[0] <= '9') {
			pid_t pid;
			if (kstrtoint(n, 10, &pid) == 0 && pid > 0 &&
			    p->d_name.name && strcmp(p->d_name.name, "proc") == 0) {
				t = find_task_by_vpid(pid);
				if (t)
					get_task_struct(t);
				break;
			}
		}
		d = p;
	}
	rcu_read_unlock();
	return t;   /* caller: put_task_struct */
}
#ifdef PKGMASK_ENABLE_B_LAYER
/* inode-based pid lookup: only for perm (has inode).
 * 6.x API: proc_pid(inode) returns struct pid * (may be NULL for
 * /proc/uptime etc). Take the task via get_pid_task. */
static struct task_struct *pid_task_from_inode(const struct inode *inode)
{
	struct task_struct *t = NULL;
	struct pid *pp;
	if (!inode || !inode->i_sb || inode->i_sb->s_magic != PROC_SUPER_MAGIC)
		return NULL;
	pp = proc_pid(inode);
	if (!pp)
		return NULL;
	rcu_read_lock();
	t = get_pid_task(pp, PIDTYPE_PID);
	rcu_read_unlock();
	return t;   /* caller: put_task_struct */
}
#endif
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
/* ---------------- readdir filter (filldir weak hook) ---------------- */
bool iterate_dir_filter(const char *name, const struct inode *dir)
{
	unsigned int i;
	size_t plen;
	if (!hide_dirents || !hook_getdents || !dir || !name)
		return false;

	/* v5: stealth proc block runs for ALL readers (incl root) and
	 * self-decides via reader_is_stealth. It must run BEFORE the
	 * global should_hide_for_current() gate, otherwise root (not in
	 * deny_uids) would be turned away here and never hide stealth. */
	if (hide_proc_enabled && (proc_name_count || stealth_count) &&
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
				/* v5: stealth — hidden from all readers */
				if (is_stealth_comm(task->comm)) {
					if (!reader_is_stealth()) {
						rcu_read_unlock();
						return true;
					}
				}
				/* v4.9 scoped (deny uid) — original logic, gated */
				if (should_hide_for_current()) {
					for (j = 0; j < proc_name_count; j++) {
						if (strcmp(task->comm, proc_names[j]) == 0) {
							rcu_read_unlock();
							return true;
						}
					}
				}
			}
			rcu_read_unlock();
		}
	}

	/* scoped/global target-path hiding respects the uid gate */
	if (!should_hide_for_current())
		return false;
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
/* ---------------- perm/getattr kretprobes ---------------- */
static struct kretprobe perm_kp;
static struct kretprobe getattr_kp;
static int perm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode *inode;
	if (!hide_dirents || !hook_perm)
		return 1;
	if (!target_count && !stealth_count)
		return 1;
	inode = (struct inode *)regs->regs[1];
	*(struct inode **)ri->data = inode;
#ifdef PKGMASK_ENABLE_B_LAYER
	/* v5 护栏：非 procfs inode 直接不进 exit */
	if (!inode || !inode->i_sb || inode->i_sb->s_magic != PROC_SUPER_MAGIC)
		return 1;
#endif
	return 0;
}
static int perm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode *inode;
	if (!hide_dirents || !hook_perm)
		return 0;
	inode = *(struct inode **)ri->data;
	/* 原路径目标隐藏（is_target_inode） */
	if (target_count && is_target_inode(inode)) {
		if (should_hide_for_current())
			regs->regs[0] = -ENOENT;
	}
#ifdef PKGMASK_ENABLE_B_LAYER
	/* v5 stealth pid 目录拦截 */
	if (stealth_count && inode) {
		struct task_struct *t = pid_task_from_inode(inode);
		if (t) {
			if (is_stealth_comm(t->comm) && !reader_is_stealth())
				regs->regs[0] = -ENOENT;
			put_task_struct(t);
		}
	}
#endif
	return 0;
}
static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path *path;
	struct inode *i;
	if (!hide_dirents || !hook_getattr)
		return 1;
	if (!target_count && !stealth_count)
		return 1;
	path = (struct path *)regs->regs[0];
	/* v5 护栏：先判后写；非 procfs path 不进 exit */
	if (!path || !path->dentry)
		return 1;
	i = d_inode(path->dentry);   /* d_inode() may return NULL */
	if (!i || !i->i_sb || i->i_sb->s_magic != PROC_SUPER_MAGIC)
		return 1;
	*(struct path **)ri->data = path;
	return 0;
}
static int getattr_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path *path;
	if (!hide_dirents || !hook_getattr)
		return 0;
	path = *(struct path **)ri->data;
	if (target_count && path && path->dentry && path->dentry->d_inode &&
	    is_target_inode(path->dentry->d_inode)) {
		if (should_hide_for_current())
			regs->regs[0] = -ENOENT;
	}
	if (stealth_count && path && path->dentry) {
		struct task_struct *t = pid_task_from_dentry(path->dentry);
		if (t) {
			if (is_stealth_comm(t->comm) && !reader_is_stealth())
				regs->regs[0] = -ENOENT;
			put_task_struct(t);
		}
	}
	return 0;
}
static int register_perm_getattr_hooks(void)
{
	int ret;
	memset(&perm_kp, 0, sizeof(perm_kp));
	perm_kp.handler = perm_exit;
	perm_kp.entry_handler = perm_entry;
	perm_kp.data_size = sizeof(void *);
	perm_kp.maxactive = 256;
	perm_kp.kp.symbol_name = "inode_permission";
	ret = register_kretprobe(&perm_kp);
	if (ret < 0) {
		pr_debug(PM_LOG_PREFIX "inode_permission hook unavailable (%d)\n", ret);
		memset(&perm_kp, 0, sizeof(perm_kp));
	}
	memset(&getattr_kp, 0, sizeof(getattr_kp));
	getattr_kp.handler = getattr_exit;
	getattr_kp.entry_handler = getattr_entry;
	getattr_kp.data_size = sizeof(void *);
	getattr_kp.maxactive = 256;
	getattr_kp.kp.symbol_name = "vfs_getattr";
	ret = register_kretprobe(&getattr_kp);
	if (ret < 0) {
		pr_debug(PM_LOG_PREFIX "vfs_getattr hook unavailable (%d)\n", ret);
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
/* ---------------- proc_comm kretprobes (ksys_read) ---------------- */
static struct kretprobe proc_comm_kp;
static bool proc_comm_hook_active;
static const char * const watched[] = {
	"comm", "cmdline", "stat", "status", "statm", "maps", "smaps",
	"environ", "exe", "mounts", "mountinfo", "oom_score",
	"fd", "fdinfo", "cgroup", "sched", "schedstat", "wchan", "syscall",
	"auxv", "personality", "loginuid", "sessionid", "cpuset", "net",
	"timers", "timerslack_ns", "patch_state", "attr", "ns", NULL
};
static int proc_comm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int fd;
	struct fd f;
	struct dentry *dentry;
	const char *name, *pname;
	int i;
	bool watched_name = false;
	*(struct fd *)ri->data = (struct fd){ NULL, 0 };
	if (!hide_proc_enabled)
		return 1;
	if (!proc_name_count && !stealth_count)
		return 1;
	/* v5: uid 门移除；stealth 必须对 root 生效 */
	if (!current->files)
		return 1;
	fd = (unsigned int)regs->regs[0];
	f = __to_fd(__fdget(fd));
	if (!f.file)
		return 1;
	dentry = f.file->f_path.dentry;
	if (!dentry) {
		fdput(f);
		return 1;
	}
	/* 早退1：父目录名必须是数字(pid) */
	if (!dentry->d_parent) {
		fdput(f);
		return 1;
	}
	pname = dentry->d_parent->d_name.name;
	if (!pname || pname[0] < '1' || pname[0] > '9') {
		fdput(f);
		return 1;
	}
	/* 早退2：文件名必须命中 watched[] */
	name = dentry->d_name.name;
	if (!name) {
		fdput(f);
		return 1;
	}
	for (i = 0; watched[i]; i++) {
		if (strcmp(name, watched[i]) == 0) {
			watched_name = true;
			break;
		}
	}
	if (!watched_name) {
		fdput(f);
		return 1;
	}
	*(struct fd *)ri->data = f;
	return 0;
}
static int proc_comm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct fd f = *(struct fd *)ri->data;
	struct task_struct *t;
	if (!f.file)
		return 0;
	t = pid_task_from_dentry(f.file->f_path.dentry);
	if (t) {
		if (is_stealth_comm(t->comm)) {
			/* stealth：任何读者（含 root）都 EOF；自我豁免 */
			if (!reader_is_stealth())
				regs->regs[0] = 0;
		} else if (is_scoped_comm(t->comm) && should_hide_for_current()) {
			regs->regs[0] = 0;
		}
		put_task_struct(t);
	}
	fdput(f);
	*(struct fd *)ri->data = (struct fd){ NULL, 0 };
	return 0;
}
static void register_proc_comm_hook(void)
{
	int ret;
	if (proc_comm_hook_active) return;
	memset(&proc_comm_kp, 0, sizeof(proc_comm_kp));
	proc_comm_kp.kp.symbol_name = "ksys_read";
	proc_comm_kp.entry_handler = proc_comm_entry;
	proc_comm_kp.handler = proc_comm_exit;
	proc_comm_kp.data_size = sizeof(struct fd);
	proc_comm_kp.maxactive = 64;
	ret = register_kretprobe(&proc_comm_kp);
	if (ret < 0) {
		pr_debug(PM_LOG_PREFIX "ksys_read (comm) probe unavailable (%d)\n", ret);
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

/* ---------------- B 层：proc_pid_lookup + pid_revalidate kretprobe ----------------
 * 让 stealth pid 的 /proc/<pid> 目录直接返回 -ENOENT。
 * 比 ksys_read/cmdline 安全：不 fdget、不抢 files->file_lock、不是 read 热路径。
 * 热路径是 lookup/revalidate，频率远低于 read。
 *
 * proc_pid_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
 *   arm64: regs[0]=inode, regs[1]=dentry, regs[2]=flags
 *   exit 返回 NULL = -ENOENT
 *
 * pid_revalidate(struct dentry *dentry, unsigned int flags)
 *   arm64: regs[0]=dentry, regs[1]=flags
 *   exit 返回 0 = d_invalid（触发重新 lookup）
 */
static struct kretprobe pid_lookup_kp;
static struct kretprobe pid_reval_kp;
static bool pid_lookup_hook_active;
static bool pid_reval_hook_active;
static bool hook_pid_lookup = false; /* B层默认关：GKI6.6 kretprobe lookup 路径 hang */
module_param(hook_pid_lookup, bool, 0600);
MODULE_PARM_DESC(hook_pid_lookup, "B-layer: hook proc_pid_lookup/pid_revalidate to hide stealth pid dirs");

static int pid_lookup_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dentry *dentry;
    const char *name;
    int lpid = 0;

    if (!hide_proc_enabled || !stealth_count)
        return 1;
    if (!hook_pid_lookup)
        return 1;

    dentry = (struct dentry *)regs->regs[1];
    if (!dentry || !dentry->d_name.name)
        return 1;
    name = dentry->d_name.name;
    /* d_name.len 护栏：不保证 NULL 结尾，用 len 限长 */
    if (dentry->d_name.len < 1 || dentry->d_name.len > 11)
        return 1;
    if (kstrtoint(name, 10, &lpid) != 0 || lpid <= 0)
        return 1;

    *(int *)ri->data = lpid;
    return 0;
}

static int pid_lookup_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int lpid = *(int *)ri->data;
    struct task_struct *t;

    if (lpid <= 0)
        return 0;

    rcu_read_lock();
    t = find_task_by_vpid(lpid);
    if (t) {
        if (is_stealth_comm(t->comm) && !reader_is_stealth())
            regs->regs[0] = 0; /* NULL = -ENOENT */
    }
    rcu_read_unlock();
    return 0;
}

static int pid_reval_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dentry *dentry;
    const char *name;
    int lpid = 0;

    if (!hide_proc_enabled || !stealth_count)
        return 1;
    if (!hook_pid_lookup)
        return 1;

    dentry = (struct dentry *)regs->regs[0];
    if (!dentry || !dentry->d_name.name)
        return 1;
    name = dentry->d_name.name;
    if (dentry->d_name.len < 1 || dentry->d_name.len > 11)
        return 1;
    if (kstrtoint(name, 10, &lpid) != 0 || lpid <= 0)
        return 1;

    *(int *)ri->data = lpid;
    return 0;
}

static int pid_reval_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int lpid = *(int *)ri->data;
    struct task_struct *t;

    if (lpid <= 0)
        return 0;

    rcu_read_lock();
    t = find_task_by_vpid(lpid);
    if (t) {
        if (is_stealth_comm(t->comm) && !reader_is_stealth())
            regs->regs[0] = 0; /* 0 = d_invalid */
    }
    rcu_read_unlock();
    return 0;
}

static int register_pid_lookup_hooks(void)
{
    int ret;

    memset(&pid_lookup_kp, 0, sizeof(pid_lookup_kp));
    pid_lookup_kp.kp.symbol_name = "proc_pid_lookup";
    pid_lookup_kp.entry_handler = pid_lookup_entry;
    pid_lookup_kp.handler = pid_lookup_exit;
    pid_lookup_kp.data_size = sizeof(int);
    pid_lookup_kp.maxactive = 256;
    ret = register_kretprobe(&pid_lookup_kp);
    if (ret < 0) {
        pr_debug(PM_LOG_PREFIX "proc_pid_lookup hook unavailable (%d)\n", ret);
        memset(&pid_lookup_kp, 0, sizeof(pid_lookup_kp));
    } else {
        pid_lookup_hook_active = true;
    }

    memset(&pid_reval_kp, 0, sizeof(pid_reval_kp));
    pid_reval_kp.kp.symbol_name = "pid_revalidate";
    pid_reval_kp.entry_handler = pid_reval_entry;
    pid_reval_kp.handler = pid_reval_exit;
    pid_reval_kp.data_size = sizeof(int);
    pid_reval_kp.maxactive = 256;
    ret = register_kretprobe(&pid_reval_kp);
    if (ret < 0) {
        pr_debug(PM_LOG_PREFIX "pid_revalidate hook unavailable (%d)\n", ret);
        memset(&pid_reval_kp, 0, sizeof(pid_reval_kp));
    } else {
        pid_reval_hook_active = true;
    }

    return 0;
}

static void unregister_pid_lookup_hooks(void)
{
    if (pid_lookup_hook_active) {
        unregister_kretprobe(&pid_lookup_kp);
        pid_lookup_hook_active = false;
    }
    if (pid_reval_hook_active) {
        unregister_kretprobe(&pid_reval_kp);
        pid_reval_hook_active = false;
    }
    memset(&pid_lookup_kp, 0, sizeof(pid_lookup_kp));
    memset(&pid_reval_kp, 0, sizeof(pid_reval_kp));
}

/* ---------------- C 层：proc_pid_cmdline_read kretprobe ----------------
 * 直接挂 procfs 自己的 cmdline read handler（kallsyms 已确认存在）。
 * arm64: regs[0]=struct file*, regs[1]=buf, regs[2]=count, regs[3]=ppos。
 * file 已被 vfs 持引用：entry 不 fdget、不加锁；exit 不 fdput。
 * 命中 stealth 且非自身读取 -> 返回 0（EOF）。
 */
static struct kretprobe cmdline_kp;
static bool cmdline_hook_active;
static bool hook_cmdline = false; /* 默认关：该 kretprobe 在本 GKI 上 hang，需换 B 层方案 */
module_param(hook_cmdline, bool, 0600);
MODULE_PARM_DESC(hook_cmdline, "C-layer: hook proc_pid_cmdline_read to EOF stealth cmdlines");

static int cmdline_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *f;
	if (!hide_proc_enabled || !stealth_count)
		return 1;
	if (!hook_cmdline)
		return 1;
	f = (struct file *)regs->regs[0];
	if (!f || !f->f_path.dentry)
		return 1;
	*(struct file **)ri->data = f;
	return 0;
}

static int cmdline_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file *f = *(struct file **)ri->data;
	struct task_struct *t;
	if (!f)
		return 0;
	t = pid_task_from_dentry(f->f_path.dentry);
	if (t) {
		if (is_stealth_comm(t->comm) && !reader_is_stealth())
			regs->regs[0] = 0;   /* 短读=EOF */
		put_task_struct(t);
	}
	return 0;
}

static int register_cmdline_hook(void)
{
	int ret;
	if (cmdline_hook_active)
		return 0;
	memset(&cmdline_kp, 0, sizeof(cmdline_kp));
	cmdline_kp.kp.symbol_name = "proc_pid_cmdline_read";
	cmdline_kp.entry_handler = cmdline_entry;
	cmdline_kp.handler = cmdline_exit;
	cmdline_kp.data_size = sizeof(struct file *);
	cmdline_kp.maxactive = 128;
	ret = register_kretprobe(&cmdline_kp);
	if (ret < 0) {
		pr_debug(PM_LOG_PREFIX "proc_pid_cmdline_read probe unavailable (%d)\n", ret);
		memset(&cmdline_kp, 0, sizeof(cmdline_kp));
		return ret;
	}
	cmdline_hook_active = true;
	pr_debug(PM_LOG_PREFIX "C-layer cmdline hook armed\n");
	return 0;
}

static void unregister_cmdline_hook(void)
{
	if (cmdline_hook_active)
		unregister_kretprobe(&cmdline_kp);
	cmdline_hook_active = false;
	memset(&cmdline_kp, 0, sizeof(cmdline_kp));
}
/* ---------------- target path resolution (unchanged) ---------------- */
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
		pr_debug(PM_LOG_PREFIX "path not resolvable: %s\n", path_str);
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
	/* alias /data/data/X <-> /data/user/0/X */
	if (strncmp(path_str, "/data/data/", 11) == 0) {
		char alias[TARGET_TEXT_LEN];
		snprintf(alias, sizeof(alias), "/data/user/0/%s", path_str + 11);
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
		snprintf(alias, sizeof(alias), "/data/data/%s", path_str + 13);
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
/* ---------------- config parsing ---------------- */
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
	stealth_count = 0;
	strscpy(tmp, buf, sizeof(tmp));
	tok = tmp;
	while (tok && *tok &&
	       (proc_name_count + stealth_count) < (2 * MAX_HIDE_PROC_NAMES)) {
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
				if (tok[0] == '!') {
					if (stealth_count < MAX_HIDE_PROC_NAMES) {
						strscpy(stealth_names[stealth_count],
							tok + 1,
							sizeof(stealth_names[0]));
						stealth_count++;
					}
				} else {
					if (proc_name_count < MAX_HIDE_PROC_NAMES) {
						strscpy(proc_names[proc_name_count],
							tok,
							sizeof(proc_names[0]));
						proc_name_count++;
					}
				}
			}
		}
		tok = comma ? comma + 1 : NULL;
	}
}
static void unregister_all_hooks(void)
{
	unregister_perm_getattr_hooks();
	unregister_proc_comm_hook();
	unregister_cmdline_hook();
	unregister_pid_lookup_hooks();
}
static int apply_config(void)
{
	trim_param(scope_mode);
	trim_param(deny_uids);
	trim_param(allow_uids);
	trim_param(target_paths);
	trim_param(hide_proc_names_buf);
	unregister_all_hooks();
	target_count = 0;
	memset(targets, 0, sizeof(targets));
	if (parse_scope_mode(scope_mode))
		return -EINVAL;
	if (parse_uid_list(deny_uids, deny_uid_list, &deny_uid_count,
			   MAX_DENY_UIDS))
		return -EINVAL;
	if (parse_uid_list(allow_uids, allow_uid_list, &allow_uid_count,
			   MAX_ALLOW_UIDS))
		return -EINVAL;
	resolve_target_paths(target_paths);
	parse_hide_proc_names(hide_proc_names_buf);
	if (hook_perm || hook_getattr)
		register_perm_getattr_hooks();
	/* 旧 ksys_read kretprobe 疑似 hang 系统，永久隔离。 */
	unregister_proc_comm_hook();
	/* B 层：proc_pid_lookup + pid_revalidate（让 stealth pid 目录返回 -ENOENT） */
	if (hide_proc_enabled && stealth_count && hook_pid_lookup)
		register_pid_lookup_hooks();
	else
		unregister_pid_lookup_hooks();
	/* C 层：proc_pid_cmdline_read（直接 file，无 fdget/无锁） */
	if (hide_proc_enabled && stealth_count && hook_cmdline)
		register_cmdline_hook();
	else
		unregister_cmdline_hook();
	return 0;
}
static void reset_state(void)
{
	unregister_all_hooks();
	target_count = 0;
	deny_uid_count = 0;
	allow_uid_count = 0;
	proc_name_count = 0;
	stealth_count = 0;
	memset(targets, 0, sizeof(targets));
	active_scope = SCOPE_DENY;
}
/* ---------------- sysfs ---------------- */
static int reload_store(const char *buf, const struct kernel_param *kp)
{
	if (buf[0] == '1')
		return apply_config();
	return -EINVAL;
}
static struct kernel_param_ops reload_ops = { .set = reload_store };
module_param_cb(reload, &reload_ops, NULL, 0600);
static int status_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE,
			 "scope=%s targets=%u\n"
			 "enabled=%d proccount=%u stealth=%u\n",
			 scope_mode, target_count,
			 hide_dirents ? 1 : 0,
			 proc_name_count, stealth_count);
}
static struct kernel_param_ops status_ops = { .get = status_get };
module_param_cb(status, &status_ops, NULL, 0400);
/* ---------------- init ---------------- */
/* ---------------- SYMBOL PROBE (safe: register+unregister immediately) -------
 * 只判断符号在不在 kallsyms，不挂任何拦截、不在 read 热路径加锁。
 * 开机后跑：dmesg | grep -E "pkgmask: SYM|pkgmask: sym"
 */
static int probe_noop(struct kprobe *p, struct pt_regs *regs) { return 0; }

static void __init probe_pid_syms(void)
{
	static const char *cands[] = {
		/* read syscall (sanity) */
		"ksys_read", "__arm64_sys_read",
		/* procfs cmdline/status read handlers */
		"proc_pid_cmdline_read", "proc_pid_cmdline_open", "proc_pid_cmdline",
		"proc_pid_status_read", "proc_pid_status", "proc_pid_status_open",
		"proc_pid_stat_read", "proc_pid_stat",
		/* directory / lookup / revalidate */
		"proc_pid_lookup", "pid_revalidate",
		"proc_pident_lookup", "proc_pident_readdir",
		"proc_fill_super", "proc_pid_readdir",
		/* file ops open/release */
		"proc_pid_open", "proc_pid_release",
		NULL
	};
	int i;
	for (i = 0; cands[i]; i++) {
		struct kprobe kp = {0};
		int ret;
		kp.symbol_name = cands[i];
		kp.pre_handler = probe_noop;
		ret = register_kprobe(&kp);
		if (ret == 0) {
			pr_info(PM_LOG_PREFIX "SYMFOUND %-28s @ %px\n",
				cands[i], (void *)kp.addr);
			unregister_kprobe(&kp);
		} else {
			pr_info(PM_LOG_PREFIX "symmiss %-28s ret=%d\n", cands[i], ret);
		}
	}
	pr_info(PM_LOG_PREFIX "symbol probe done\n");
}

static int __init xk7a9f_init(void)
{
#ifdef CONFIG_PKGMASK_HWID
	xw3e8b_init();
#endif
	probe_pid_syms();
	pr_debug(PM_LOG_PREFIX "v5.0 built-in initialized (deferred kretprobe)\n");
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
MODULE_DESCRIPTION("pkgmask v5.1 (built-in, B-layer pid_lookup/revalidate + stealth)");
//（注：内容由AI生成）
