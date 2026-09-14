#!/system/bin/sh
# 内核能力信息（只读诊断）
. "${0%/*}/lib_common.sh"
echo "uname: $(uname -a)"
echo "--- 关键模块节点 ---"
for d in susfs kernelsu pkgmask; do
    if [ -d /sys/module/$d ]; then echo "[$d] present"; else echo "[$d] absent"; fi
done
echo "--- pkgmask 参数节点 ---"
ls "$PKG_SYSFS" 2>/dev/null
echo "--- hwid 状态 ---"
cat "$HWID_SYSFS/hwid_status" 2>/dev/null || echo "hwid_spoof 不存在"
echo "--- pkgmask status ---"
cat "$PKG_SYSFS/status" 2>/dev/null
echo "--- SUSFS ---"
cat /sys/module/susfs/version 2>/dev/null || echo "susfs 不存在"
echo "--- SELinux ---"
getenforce 2>/dev/null
