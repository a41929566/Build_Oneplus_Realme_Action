#!/system/bin/sh
# status_now.sh - 实时读 sysfs 生成精简 status.json
# 由 WebUI shExec 调用，不需要常驻 daemon

# 统一走 lib_common.sh 的 sysfs 路径解析（hwid 可能内建于 pkgmask）
. "$(dirname "$0")/lib_common.sh"
PKG="$PKG_SYSFS"
HWID="$HWID_SYSFS"

# pkgmask
scope=$(cat $PKG/scope_mode 2>/dev/null || echo "")
deny=$(cat $PKG/deny_uids 2>/dev/null || echo "")
targets=$(cat $PKG/target_paths 2>/dev/null || echo "")
hprocen=$(cat $PKG/hide_proc_enabled 2>/dev/null || echo "0")
hprocn=$(cat $PKG/hide_proc_names 2>/dev/null || echo "")
status=$(cat $PKG/status 2>/dev/null || echo "")
hperm=$(cat $PKG/hook_perm 2>/dev/null || echo "N")
hgetattr=$(cat $PKG/hook_getattr 2>/dev/null || echo "N")
hgetdents=$(cat $PKG/hook_getdents 2>/dev/null || echo "N")
hdirents=$(cat $PKG/hide_dirents 2>/dev/null || echo "N")

# hwid
hwen=$(cat $HWID/hwid_enabled 2>/dev/null || echo "0")
hwactive=$(cat $HWID/hwid_status 2>/dev/null | grep -o 'hook_active=[01]' | cut -d= -f2 || echo "0")

# props
serial=$(getprop ro.serialno 2>/dev/null || echo "")
fp=$(getprop ro.build.fingerprint 2>/dev/null || echo "")
vb=$(getprop ro.boot.verifiedbootstate 2>/dev/null || echo "")
model=$(getprop ro.product.model 2>/dev/null || echo "")

# kernel
kver=$(uname -r 2>/dev/null || echo "")

# selfcheck 结果
sc_pass=0; sc_warn=0; sc_fail=0
if [ -f /data/adb/modules/susfs_env_guard/run/selfcheck.txt ]; then
  sc_pass=$(grep -c "st.*ok" /data/adb/modules/susfs_env_guard/run/selfcheck.txt 2>/dev/null || echo 0)
  sc_warn=$(grep -c "st.*warn" /data/adb/modules/susfs_env_guard/run/selfcheck.txt 2>/dev/null || echo 0)
  sc_fail=$(grep -c "st.*fail" /data/adb/modules/susfs_env_guard/run/selfcheck.txt 2>/dev/null || echo 0)
fi

# JSON 转义
esc() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'
}

echo "{"
echo "  \"ts\": $(date +%s),"
echo "  \"pkgmask\": {"
echo "    \"scope\": \"$(esc "$scope")\","
echo "    \"deny_uids\": \"$(esc "$deny")\","
echo "    \"target_paths\": \"$(esc "$targets")\","
echo "    \"hide_proc\": $hprocen,"
echo "    \"hide_proc_names\": \"$(esc "$hprocn")\","
echo "    \"status\": \"$(esc "$status")\","
echo "    \"hook_perm\": \"$hperm\","
echo "    \"hook_getattr\": \"$hgetattr\","
echo "    \"hook_getdents\": \"$hgetdents\","
echo "    \"hide_dirents\": \"$hdirents\""
echo "  },"
echo "  \"hwid\": {"
echo "    \"enabled\": \"$hwen\","
echo "    \"hook_active\": \"$hwactive\""
echo "  },"
echo "  \"props\": {"
echo "    \"serial\": \"$(esc "$serial")\","
echo "    \"fingerprint\": \"$(esc "$fp")\","
echo "    \"vbstate\": \"$(esc "$vb")\","
echo "    \"model\": \"$(esc "$model")\""
echo "  },"
echo "  \"kernel\": {\"version\": \"$(esc "$kver")\"},"
echo "  \"selfcheck\": {\"pass\": $sc_pass, \"warn\": $sc_warn, \"fail\": $sc_fail}"
echo "}"
#（注：内容由AI生成）
