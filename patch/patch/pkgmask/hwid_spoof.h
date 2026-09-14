/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hwid_spoof -- kernel-level read-only hardware ID spoofing.
 *
 * Compiled into the same built-in object as pkgmask (CONFIG_PKGMASK=y).
 * Every hook is a dynamic kretprobe on the stable vfs_read() entry; if a
 * symbol is unavailable the probe simply fails to register and the rest of
 * the kernel boots normally (no hard symbol dependency, no core-source
 * edit, therefore no boot risk).
 */
#ifndef __HWID_SPOOF_H__
#define __HWID_SPOOF_H__

#if IS_ENABLED(CONFIG_PKGMASK_HWID)
int  hwid_spoof_init(void);
void hwid_spoof_exit(void);
#else
static inline int hwid_spoof_init(void) { return 0; }
static inline void hwid_spoof_exit(void) { }
#endif

#endif /* __HWID_SPOOF_H__ */
