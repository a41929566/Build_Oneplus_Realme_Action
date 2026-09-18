// SPDX-License-Identifier: GPL-2.0
/*
 * pkgmask v4.15 -- kernel-level app package / directory hiding
 *
 * v4.15 changes:
 *   - proc_comm kretprobe hook point changed from vfs_read to ksys_read
 *     Reason: vfs_read is LTO-inlined on GKI 6.6; the probe never fires.
 *   - proc_comm_entry now converts fd to struct fd via __fdget and stores
 *     the fd for the exit handler; exit handler releases with fdput.
 *   - proc_comm data_size changed from sizeof(void*) to sizeof(struct fd).
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

bool iterate_dir_filter(const char *name, const struct inode *dir)
{
	unsigned int i;
	size_t plen;

	if (!hide_dirents || !hook_getdents || !dir || !name)
		return false;
	if (!should_hide_for_current())
		return false;

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

/* v4.15: proc_comm kretprobe hook on ksys_read (vfs_read is LTO-inlined) */
static struct kretprobe proc_comm_kp;
static bool proc_comm_hook_active;

static int proc_comm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned int fd;
	struct fd f;
	struct dentry *dentry;
	const char *name;

	*(struct fd *)ri->data = (struct fd){ NULL, 0 };

	if (!hide_proc_enabled || !proc_name_count)
		return 0;

	if (active_scope == SCOPE_DENY) {
		uid_t uid = from_kuid(&init_user_ns, current_uid());
		if (!is_in_uid_list(deny_uid_list, deny_uid_count, uid))
			return 0;
	}

	fd = (unsigned int)regs->regs[0];
	f = __to_fd(__fdget(fd));
	if (!f.file)
		return 0;

	dentry = f.file->f_path.dentry;
	if (!dentry) {
		fdput(f);
		return 0;
	}

	name = dentry->d_name.name;
	if (strcmp(name, "comm") != 0) {
		fdput(f);
		return 0;
	}

	if (dentry->d_parent) {
		const char *pname = dentry->d_parent->d_name.name;
		if (pname[0] >= '1' && pname[0] <= '9') {
			*(struct fd *)ri->data = f;
			return 0;
		}
	}
	fdput(f);
	return 0;
}

static int proc_comm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct fd f = *(struct fd *)ri->data;
	struct dentry *dentry;
	struct task_struct *task;
	int lpid;
	unsigned int j;

	if (!f.file)
		return 0;

	dentry = f.file->f_path.dentry;
	if (!dentry || !dentry->d_parent)
		goto out;

	if (kstrtoint(dentry->d_parent->d_name.name, 10, &lpid) != 0 || lpid <= 0)
		goto out;

	rcu_read_lock();
	task = find_task_by_vpid(lpid);
	if (task) {
		for (j = 0; j < proc_name_count; j++) {
			if (strcmp(task->comm, proc_names[j]) == 0) {
				rcu_read_unlock();
				regs->regs[0] = 0;
				goto out;
			}
		}
	}
	rcu_read_unlock();
out:
	fdput(f);
	*(struct fd *)ri->data = (struct fd){ NULL, 0 };
	return 0;
}

static void register_proc_comm_hook(void)
{
	int ret;
	if (proc_comm_hook_active) return;
	memset(&proc_comm_kp, 0, sizeof(proc_comm_kp));
	/* v4.15: ksys_read instead of vfs_read (vfs_read is LTO-inlined) */
	proc_comm_kp.kp.symbol_name = "ksys_read";
	proc_comm_kp.entry_handler = proc_comm_entry;
	proc_comm_kp.handler = proc_comm_exit;
	proc_comm_kp.data_size = sizeof(struct fd);
	proc_comm_kp.maxactive = 64;
	ret = register_kretprobe(&proc_comm_kp);
	if (ret < 0) {
		pr_info(PM_LOG_PREFIX "ksys_read (comm) probe unavailable (%d)\n", ret);
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
#ifdef CONFIG_PKGMASK_HWID
	xw3e8b_init();
#endif

	pr_debug(PM_LOG_PREFIX "v4.15 built-in initialized (deferred kretprobe registration)\n");
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
MODULE_DESCRIPTION("pkgmask v4.15 kernel-level package hiding (built-in, ksys_read hook)");
