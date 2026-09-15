#!/system/bin/sh
# SUSFS环境守护 v6.3 - post-fs-data.sh（zygote 启动前执行）
# 极早期阶段：负责所有 ro.* 属性的伪装（必须在此阶段，zygote 启动后 ro.* 锁死，否则永远改不动）
MODDIR=${0%/*}
. "$MODDIR/tools/lib_common.sh"

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$DATA_DIR/logs" "$RUN_DIR"

# 首次安装生成默认配置（正常情况 customize.sh 已覆盖，这里只兜底）
[ -f "$CONF" ] || cp -f "$MODDIR/config/spoof.conf.example" "$CONF"
init_feature_flags

# 应用本模块 SELinux 规则。
if [ -f "$MODDIR/sepolicy.rule" ]; then
    "$MAGISKPOLICY" --apply "$MODDIR/sepolicy.rule" 2>/dev/null
fi

# ============================================================
# 核心修改：在 zygote 启动前执行属性伪装！
# 原因：ro.*（如 ro.boot.verifiedbootstate, ro.build.fingerprint）
#       必须在系统启动的最早期用 resetprop 覆盖，晚于此阶段将无法修改。
# ============================================================
if [ -f "$MODDIR/tools/props_spoof.sh" ]; then
    sh "$MODDIR/tools/props_spoof.sh" apply >> "$RUN_DIR/props_post_fs.log" 2>&1
fi

# 注意：内核 hwid 和 android_id 依旧延后到 service.sh 执行
# 原因：zygote 启动前挂 vfs_read kretprobe 可能导致系统级重启
