#!/system/bin/sh
# SUSFS环境守护 v6.3 - post-fs-data.sh（zygote 启动前执行，最关键时机）
# 所有 ro.* 属性伪装必须在此完成，使 app 从 zygote fork 时 JVM 固化值即为假值，
# 从而 JVM / getprop / native PropertyUtil 三通道一致（Maple 交叉比对才不会暴露）。
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

# === 属性伪装（必须在 zygote 前）===
sh "$MODDIR/tools/props_spoof.sh" apply > "$RUN_DIR/props_pfd.log" 2>&1

# === 内核只读硬件 ID（built-in 节点此阶段已就绪）===
sh "$MODDIR/tools/randomize.sh" apply > "$RUN_DIR/hwid_pfd.log" 2>&1