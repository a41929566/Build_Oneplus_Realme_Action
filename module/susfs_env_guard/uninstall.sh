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
sh "$MODDIR/tools/device_model.sh" restore 2>/dev/null

# 删除本模块数据
rm -rf /data/adb/susfs_env_guard 2>/dev/null
rm -f /data/adb/pkgmask/config.conf 2>/dev/null

# 清理 NeoZygisk 运行时
rm -rf /data/adb/neozygisk 2>/dev/null

# 清理 DRM ID Virtualizer 状态
rm -rf /data/local/tmp/drmid_probe_state 2>/dev/null

# 清理 Per-App Props 在根目录留下的标记与配置（post-fs-data.sh 创建）。
# 旧版卸载脚本遗漏了这些：它们位于 / 根分区，虽然重启后会消失，
# 但在「卸载后不重启」的窗口里仍可被检测方读到，属于残留指纹。
rm -f /.managed_by_skp_rezygisk 2>/dev/null
rm -f /.rezygisk-runtime 2>/dev/null
rm -f /.per_app_props_features 2>/dev/null
rm -rf /.per-app-props 2>/dev/null

exit 0

