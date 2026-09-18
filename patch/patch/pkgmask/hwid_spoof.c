/* Force rebuild v4 - ksys_read hook (vfs_read inlined by LTO) */
// SPDX-License-Identifier: GPL-2.0
/*
 * hwid_spoof -- kernel-level read-only hardware ID spoofing (v1.1)
 *
 * v1.1 changes:
 *   - hook point changed from vfs_read to ksys_read
 *     Reason: on GKI 6.6 with LTO+O2, vfs_read is inlined into ksys_read.
 *   - entry handler converts fd (arg0 of ksys_read) to struct file * via __fdget
 */

#if defined(__has_include)
# if __has_include(<linux/stdarg.h>)
#  include <linux/stdarg.h>
# else
#  include <stdarg.h>
# endif
#else
# include <stdarg.h>
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/magic.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/version.h>

#if defined(CONFIG_ARM64)
#define HW_LOG_PREFIX "hwid_spoof: "
#define HWID_MAX_BYTES   16384
#define HWID_UID_MAX     128
#define HWID_UID_LEN     1024
#define HWID_HEX_LEN     64
#define HWID_MAC_LEN     18

enum hwid_kind {
	KIND_NONE = 0,
	KIND_SOC,
	KIND_CID,
	KIND_WLAN_MAC,
	KIND_BT_MAC,
	KIND_CPUINFO,
};

static bool hwid_enabled;
static int hwid_enabled_set(const char *buf, const struct kernel_param *kp);
static int hwid_enabled_get(char *buffer, const struct kernel_param *kp);
static const struct kernel_param_ops hwid_enabled_ops = {
	.set = hwid_enabled_set,
	.get = hwid_enabled_get,
};
module_param_cb(hwid_enabled, &hwid_enabled_ops, NULL, 0600);
MODULE_PARM_DESC(hwid_enabled, "Master switch for read-only hardware ID spoof");

static char hwid_uids_buf[HWID_UID_LEN];
module_param_string(hwid_uids, hwid_uids_buf, sizeof(hwid_uids_buf), 0600);
MODULE_PARM_DESC(hwid_uids, "Comma-separated UIDs to spoof for; empty = global");

static char cfg_soc[HWID_HEX_LEN];
module_param_string(hwid_soc_serial, cfg_soc, sizeof(cfg_soc), 0600);
MODULE_PARM_DESC(hwid_soc_serial, "Fake SoC serial (hex)");

static char cfg_cid[HWID_HEX_LEN];
module_param_string(hwid_cid, cfg_cid, sizeof(cfg_cid), 0600);
MODULE_PARM_DESC(hwid_cid, "Fake storage CID (32 hex)");

static char cfg_wmac[HWID_MAC_LEN];
module_param_string(hwid_wlan_mac, cfg_wmac, sizeof(cfg_wmac), 0600);
MODULE_PARM_DESC(hwid_wlan_mac, "Fake wlan MAC aa:bb:cc:dd:ee:ff");

static char cfg_bmac[HWID_MAC_LEN];
module_param_string(hwid_bt_mac, cfg_bmac, sizeof(cfg_bmac), 0600);
MODULE_PARM_DESC(hwid_bt_mac, "Fake Bluetooth MAC aa:bb:cc:dd:ee:ff");

static char cfg_cpuser[HWID_HEX_LEN];
module_param_string(hwid_cpu_serial, cfg_cpuser, sizeof(cfg_cpuser), 0600);
MODULE_PARM_DESC(hwid_cpu_serial, "Fake /proc/cpuinfo Serial (16 hex)");

static char fixed_soc[HWID_HEX_LEN];
static char fixed_cid[33];
static char fixed_wmac[HWID_MAC_LEN];
static char fixed_bmac[HWID_MAC_LEN];
static char fixed_cpuser[17];

static uid_t hwid_uid_list[HWID_UID_MAX];
static unsigned int hwid_uid_count;

static void hwid_copy(char *dst, const char *src, size_t n)
{
	size_t i;

	if (!n)
		return;
	if (src) {
		for (i = 0; i + 1 < n && src[i]; i++)
			dst[i] = src[i];
		dst[i] = '\0';
	} else {
		dst[0] = '\0';
	}
}

static void hwid_chomp(char *s)
{
	size_t len;

	if (!s)
		return;
	len = strlen(s);
	while (len && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
		       s[len - 1] == ' ' || s[len - 1] == '\t'))
		s[--len] = '\0';
}

static bool hwid_uid_match(void)
{
	uid_t uid;
	unsigned int i;

	if (hwid_uid_count == 0)
		return true;
	uid = from_kuid(&init_user_ns, current_uid());
	for (i = 0; i < hwid_uid_count; i++)
		if (hwid_uid_list[i] == uid)
			return true;
	return false;
}

static void hwid_parse_uids(void)
{
	char tmp[HWID_UID_LEN];
	char *tok, *comma;

	hwid_uid_count = 0;
	hwid_copy(tmp, hwid_uids_buf, sizeof(tmp));
	tok = tmp;
	while (tok && *tok && hwid_uid_count < HWID_UID_MAX) {
		comma = strchr(tok, ',');
		if (comma)
			*comma = '\0';
		tok += strspn(tok, " \t\n\r");
		if (*tok) {
			unsigned int v;

			if (kstrtouint(tok, 10, &v) == 0)
				hwid_uid_list[hwid_uid_count++] = (uid_t)v;
		}
		tok = comma ? comma + 1 : NULL;
	}
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static bool is_mac_char(char c)
{
	return isxdigit((unsigned char)c) || c == ':';
}

static void gen_mac(char out[HWID_MAC_LEN])
{
	u8 b[6];

	get_random_bytes(b, 6);
	b[0] &= 0xfc;
	b[0] |= 0x02;
	scnprintf(out, HWID_MAC_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
		  b[0], b[1], b[2], b[3], b[4], b[5]);
}

static void gen_hex(char *out, size_t n)
{
	static const char hx[] = "0123456789abcdef";
	size_t i;
	u8 r = 0;

	for (i = 0; i < n; i++) {
		if ((i & 1) == 0)
			get_random_bytes(&r, 1);
		out[i] = hx[r & 0xf];
		r >>= 4;
	}
	out[n] = '\0';
}

static bool valid_mac(const char *s)
{
	int i;

	if (!s || strlen(s) != 17)
		return false;
	for (i = 0; i < 17; i++) {
		if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
			if (s[i] != ':')
				return false;
		} else if (!isxdigit((unsigned char)s[i])) {
			return false;
		}
	}
	return true;
}

static size_t hex_run(const char *p, size_t cap)
{
	size_t n = 0;

	while (n < cap && hexval(p[n]) >= 0)
		n++;
	return n;
}

static bool rewrite_mac(char *buf, size_t len, size_t start, const char *mac)
{
	size_t i;

	if (start + 17 > len)
		return false;
	for (i = 0; i < 17; i++)
		buf[start + i] = mac[i];
	return true;
}

static bool rewrite_soc(char *buf, size_t len)
{
	size_t i, best = 0, bestlen = 0;
	size_t slen = strlen(fixed_soc);

	for (i = 0; i < len; ) {
		if (isxdigit((unsigned char)buf[i])) {
			size_t rl = hex_run(buf + i, len - i);

			if (rl > bestlen) {
				bestlen = rl;
				best = i;
			}
			i += rl ? rl : 1;
		} else {
			i++;
		}
	}
	if (bestlen < 4 || !slen)
		return false;
	for (i = 0; i < bestlen; i++)
		buf[best + i] = fixed_soc[i % slen];
	return true;
}

static bool rewrite_cid(char *buf, size_t len)
{
	size_t i;

	for (i = 0; i + 32 <= len; ) {
		if (hexval(buf[i]) >= 0 && hex_run(buf + i, len - i) >= 32) {
			size_t k;

			for (k = 0; k < 32; k++)
				buf[i + k] = fixed_cid[k];
			return true;
		}
		i++;
	}
	return false;
}

static bool rewrite_cpuinfo(char *buf, size_t len)
{
	size_t i;
	size_t slen = strlen(fixed_cpuser);

	if (!slen)
		return false;
	for (i = 0; i + 6 < len; i++) {
		if (strncmp(buf + i, "Serial", 6) == 0) {
			size_t j = i + 6;

			while (j < len && buf[j] != ':')
				j++;
			if (j >= len)
				continue;
			j++;
			while (j < len && (buf[j] == ' ' || buf[j] == '\t'))
				j++;
			if (j < len && hexval(buf[j]) >= 0) {
				size_t rl = hex_run(buf + j, len - j);
				size_t k;

				if (rl < 8)
					continue;
				for (k = 0; k < rl; k++)
					buf[j + k] = fixed_cpuser[k % slen];
				return true;
			}
		}
	}
	return false;
}

static bool rewrite_mac_scan(char *buf, size_t len, const char *mac)
{
	size_t i;
	bool changed = false;

	if (!mac || strlen(mac) < 12)
		return false;

	for (i = 0; i + 17 <= len; ) {
		if (is_mac_char(buf[i]) &&
		    hexval(buf[i]) >= 0 && hexval(buf[i + 1]) >= 0 &&
		    buf[i + 2] == ':' && hexval(buf[i + 3]) >= 0 &&
		    hexval(buf[i + 4]) >= 0 && buf[i + 5] == ':' &&
		    hexval(buf[i + 6]) >= 0 && hexval(buf[i + 7]) >= 0 &&
		    buf[i + 8] == ':' && hexval(buf[i + 9]) >= 0 &&
		    hexval(buf[i + 10]) >= 0 && buf[i + 11] == ':' &&
		    hexval(buf[i + 12]) >= 0 && hexval(buf[i + 13]) >= 0 &&
		    buf[i + 14] == ':' && hexval(buf[i + 15]) >= 0 &&
		    hexval(buf[i + 16]) >= 0) {
			bool left_ok = (i == 0) || !is_mac_char(buf[i - 1]);
			char after = (i + 17 < len) ? buf[i + 17] : '\0';
			bool right_ok = (after == '\0' || after == '\n' ||
					 after == '\r' || after == ' ' ||
					 after == '\t' || !is_mac_char(after));

			if (left_ok && right_ok) {
				rewrite_mac(buf, len, i, mac);
				changed = true;
				i += 17;
				continue;
			}
		}
		i++;
	}
	if (changed)
		return true;

	for (i = 0; i + 12 <= len; ) {
		if (hexval(buf[i]) >= 0 && hex_run(buf + i, len - i) >= 12) {
			bool left_ok = (i == 0) || !isxdigit((unsigned char)buf[i - 1]);
			char after = (i + 12 < len) ? buf[i + 12] : '\0';
			bool right_ok = !isxdigit((unsigned char)after);

			if (left_ok && right_ok) {
				size_t k, mi = 0;

				for (k = 0; k < 12; k++) {
					while (mac[mi] == ':')
						mi++;
					buf[i + k] = mac[mi++];
				}
				changed = true;
				i += 12;
				continue;
			}
		}
		i++;
	}
	return changed;
}

static const char *dname(struct dentry *d)
{
	return d ? (const char *)d->d_name.name : NULL;
}

static bool hwid_is_bt_iface(const char *name)
{
	return name && (!strncmp(name, "hci", 3) ||
			!strcmp(name, "bt-ipv6"));
}

static bool hwid_is_wifi_iface(const char *name)
{
	if (!name)
		return false;
	return !strncmp(name, "wlan", 4) || !strncmp(name, "wlp", 3) ||
	       !strncmp(name, "wifi", 4) || !strncmp(name, "swlan", 5) ||
	       !strncmp(name, "p2p", 3) || !strncmp(name, "eth", 3);
}

static enum hwid_kind classify(struct file *file)
{
	struct dentry *d = file->f_path.dentry;
	struct dentry *parent;
	struct inode *inode;
	const char *name, *pname;
	int magic;

	if (!d)
		return KIND_NONE;
	inode = d_inode(d);
	if (!inode || !inode->i_sb)
		return KIND_NONE;
	name = dname(d);
	parent = d->d_parent;
	pname = dname(parent);
	if (!name)
		return KIND_NONE;
	magic = inode->i_sb->s_magic;

	if (magic == PROC_SUPER_MAGIC && strcmp(name, "cpuinfo") == 0 &&
	    (!pname || !strcmp(pname, "/") || !strcmp(pname, "proc")))
		return KIND_CPUINFO;

	if (magic != SYSFS_MAGIC)
		return KIND_NONE;

	if (strcmp(name, "serial_number") == 0 &&
	    pname && (!strcmp(pname, "soc0") || !strcmp(pname, "soc")))
		return KIND_SOC;

	if (strcmp(name, "cid") == 0 && pname && !strcmp(pname, "device"))
		return KIND_CID;

	if (strcmp(name, "address") == 0 && pname) {
		if (hwid_is_bt_iface(pname))
			return KIND_BT_MAC;
		if (hwid_is_wifi_iface(pname)) {
			if (strcmp(pname, "lo") && strncmp(pname, "rmnet", 5) &&
			    strncmp(pname, "dummy", 5) && strncmp(pname, "sit", 3))
				return KIND_WLAN_MAC;
		}
	}
	return KIND_NONE;
}

struct hwid_hit {
	char __user *buf;
	enum hwid_kind kind;
	struct fd f;
	bool f_valid;
};

static struct kretprobe vfs_read_kp;
static bool hwid_hook_active;
static int hwid_hook_register(void);
static void hwid_hook_unregister(void);

static int hwid_enabled_set(const char *buf, const struct kernel_param *kp)
{
	bool enable;
	int ret;

	ret = kstrtobool(buf, &enable);
	if (ret)
		return ret;
	if (enable) {
		ret = hwid_hook_register();
		if (ret)
			return ret;
		hwid_enabled = true;
	} else {
		hwid_enabled = false;
		hwid_hook_unregister();
	}
	return 0;
}

static int hwid_enabled_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", hwid_enabled ? 1 : 0);
}

static int hwid_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hwid_hit *hit = (struct hwid_hit *)ri->data;
	unsigned int fd;
	struct fd f;
	enum hwid_kind kind;

	hit->buf = NULL;
	hit->kind = KIND_NONE;
	hit->f_valid = false;

	if (!hwid_enabled)
		return 0;

	fd = (unsigned int)regs->regs[0];
	f = __to_fd(__fdget(fd));
	if (!f.file)
		return 0;

	kind = classify(f.file);
	if (kind == KIND_NONE || !hwid_uid_match()) {
		fdput(f);
		return 0;
	}

	hit->f = f;
	hit->f_valid = true;
	hit->buf = (char __user *)regs->regs[1];
	hit->kind = kind;
	return 0;
}

static int hwid_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hwid_hit *hit = (struct hwid_hit *)ri->data;
	long n;
	char *tmp;
	bool changed = false;

	if (!hit->f_valid)
		return 0;

	n = (long)regs->regs[0];
	if (n <= 0 || n > HWID_MAX_BYTES)
		goto out;

	tmp = kmalloc(n, GFP_ATOMIC);
	if (!tmp)
		goto out;

	if (__copy_from_user_inatomic(tmp, hit->buf, n)) {
		kfree(tmp);
		goto out;
	}

	switch (hit->kind) {
	case KIND_SOC:
		changed = rewrite_soc(tmp, n);
		break;
	case KIND_CID:
		changed = rewrite_cid(tmp, n);
		break;
	case KIND_CPUINFO:
		changed = rewrite_cpuinfo(tmp, n);
		break;
	case KIND_WLAN_MAC:
		changed = rewrite_mac_scan(tmp, n, fixed_wmac);
		break;
	case KIND_BT_MAC:
		changed = rewrite_mac_scan(tmp, n, fixed_bmac);
		break;
	default:
		break;
	}

	if (changed && __copy_to_user_inatomic(hit->buf, tmp, n))
		pr_info_ratelimited(HW_LOG_PREFIX "write-back skipped\n");
	kfree(tmp);
out:
	fdput(hit->f);
	hit->f_valid = false;
	return 0;
}

static void hwid_refresh_fixed(void)
{
	hwid_chomp(cfg_soc);
	hwid_chomp(cfg_cid);
	hwid_chomp(cfg_wmac);
	hwid_chomp(cfg_bmac);
	hwid_chomp(cfg_cpuser);
	hwid_chomp(hwid_uids_buf);

	if (strlen(cfg_soc) >= 4)
		hwid_copy(fixed_soc, cfg_soc, sizeof(fixed_soc));
	if (strlen(fixed_soc) < 4)
		gen_hex(fixed_soc, 16);

	if (hex_run(cfg_cid, strlen(cfg_cid)) == 32 && strlen(cfg_cid) == 32)
		hwid_copy(fixed_cid, cfg_cid, sizeof(fixed_cid));
	if (strlen(fixed_cid) != 32)
		gen_hex(fixed_cid, 32);

	if (valid_mac(cfg_wmac))
		hwid_copy(fixed_wmac, cfg_wmac, sizeof(fixed_wmac));
	if (!valid_mac(fixed_wmac))
		gen_mac(fixed_wmac);

	if (valid_mac(cfg_bmac))
		hwid_copy(fixed_bmac, cfg_bmac, sizeof(fixed_bmac));
	if (!valid_mac(fixed_bmac))
		gen_mac(fixed_bmac);

	if (hex_run(cfg_cpuser, strlen(cfg_cpuser)) >= 16 &&
	    strlen(cfg_cpuser) >= 16)
		hwid_copy(fixed_cpuser, cfg_cpuser, sizeof(fixed_cpuser));
	if (strlen(fixed_cpuser) < 16)
		gen_hex(fixed_cpuser, 16);

	hwid_parse_uids();
}

static int hwid_status_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE,
		"enabled=%d hook_active=%d scope_uids=%u\n",
		hwid_enabled ? 1 : 0, hwid_hook_active ? 1 : 0, hwid_uid_count);
}

static struct kernel_param_ops hwid_status_ops = {
	.get = hwid_status_get,
};
module_param_cb(hwid_status, &hwid_status_ops, NULL, 0400);

static int hwid_reload_store(const char *buf, const struct kernel_param *kp)
{
	if (buf[0] == '1') {
		hwid_refresh_fixed();
		return 0;
	}
	return -EINVAL;
}

static struct kernel_param_ops hwid_reload_ops = {
	.set = hwid_reload_store,
};
module_param_cb(hwid_reload, &hwid_reload_ops, NULL, 0600);

static int hwid_hook_register(void)
{
	int ret;

	if (hwid_hook_active)
		return 0;
	memset(&vfs_read_kp, 0, sizeof(vfs_read_kp));
	/* v1.1: ksys_read instead of vfs_read (vfs_read is LTO-inlined) */
	vfs_read_kp.kp.symbol_name = "ksys_read";
	vfs_read_kp.handler = hwid_handler;
	vfs_read_kp.entry_handler = hwid_entry;
	vfs_read_kp.data_size = sizeof(struct hwid_hit);
	vfs_read_kp.maxactive = 512;
	ret = register_kretprobe(&vfs_read_kp);
	if (ret < 0) {
		pr_info(HW_LOG_PREFIX "ksys_read probe unavailable (%d)\n", ret);
		memset(&vfs_read_kp, 0, sizeof(vfs_read_kp));
		return ret;
	}
	hwid_hook_active = true;
	return 0;
}

static void hwid_hook_unregister(void)
{
	if (hwid_hook_active)
		unregister_kretprobe(&vfs_read_kp);
	hwid_hook_active = false;
	memset(&vfs_read_kp, 0, sizeof(vfs_read_kp));
}

int xw3e8b_init(void)
{
	memset(fixed_soc, 0, sizeof(fixed_soc));
	memset(fixed_cid, 0, sizeof(fixed_cid));
	memset(fixed_wmac, 0, sizeof(fixed_wmac));
	memset(fixed_bmac, 0, sizeof(fixed_bmac));
	memset(fixed_cpuser, 0, sizeof(fixed_cpuser));
	hwid_refresh_fixed();
	hwid_enabled = false;
	hwid_hook_active = false;
	pr_debug(HW_LOG_PREFIX "initialized; hook is opt-in\n");
	return 0;
}

void xw3e8b_exit(void)
{
	hwid_enabled = false;
	hwid_hook_unregister();
}

#else

int xw3e8b_init(void) { return 0; }
void xw3e8b_exit(void) { }

#endif
