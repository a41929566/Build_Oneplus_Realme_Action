/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PKGMASK_H
#define _LINUX_PKGMASK_H

#include <linux/types.h>

#ifdef CONFIG_PKGMASK
extern bool pkgmask_is_stealth_pid(pid_t pid);
#else
static inline bool pkgmask_is_stealth_pid(pid_t pid) { return false; }
#endif

#endif /* _LINUX_PKGMASK_H */
//（注：内容由AI生成）
