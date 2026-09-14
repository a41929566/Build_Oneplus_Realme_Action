#!/system/bin/sh
# 卸载清理：还原本模块改动（重启完成）
MODDIR=${0%/*}
. "$MODDIR/tools/lib_common.sh" 2>/dev/null

# 先停止守护进程，避免删除状态目录后仍有后台进程写入旧路径
if [ -f "$MODDIR/run/daemon.pid" ]; then
    PID=$(cat "$MODDIR/run/daemon.pid" 2>/dev/null)
    case "$PID" in
        ''|*[!0-9]*) ;;
        *) kill "$PID" 2>/dev/null || true ;;
    esac
    i=0
    while [ $i -lt 10 ] && kill -0 "$PID" 2>/dev/null; do
        sleep 1
        i=$((i+1))
    done
fi

# 还原属性覆盖
sh "$MODDIR/tools/props_spoof.sh" restore 2>/dev/null
sh "$MODDIR/tools/randomize.sh" restore 2>/dev/null
sh "$MODDIR/tools/pkgmask_setup.sh" restore 2>/dev/null
sh "$MODDIR/tools/appops_setup.sh" restore 2>/dev/null
# 卸载用户态 hwid bind mount
sh "$MODDIR/tools/hwid_userspace.sh" umount 2>/dev/null

# 删除本模块数据
rm -rf /data/adb/susfs_env_guard 2>/dev/null
rm -f /data/adb/pkgmask/config.conf 2>/dev/null
exit 0