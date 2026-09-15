#!/system/bin/sh
# SUSFS环境守护 v6.3 - post-fs-data.sh（zygote 启动前执行）
# 只做最基础的文件准备，所有属性/内核操作延后到 service.sh
# 避免在 zygote 前修改任何属性，导致系统启动完整性校验失败
MODDIR=${0%/*}
. "$MODDIR/tools/lib_common.sh"

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$DATA_DIR/logs" "$RUN_DIR"

# 首次安装生成默认配置
[ -f "$CONF" ] || cp -f "$MODDIR/config/spoof.conf.example" "$CONF"
init_feature_flags

# 应用本模块 SELinux 规则。
if [ -f "$MODDIR/sepolicy.rule" ]; then
    "$MAGISKPOLICY" --apply "$MODDIR/sepolicy.rule" 2>/dev/null
fi

# 所有属性伪装 / 内核 hwid / android_id 全部延后到 service.sh
# 原因：zygote 启动前修改 ro.* 属性或挂 vfs_read kretprobe 都可能导致系统级重启
