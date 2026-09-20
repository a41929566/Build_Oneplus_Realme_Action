#!/system/bin/sh
# ============================================================
# susfs_env_guard post-fs-data.sh（修复版：m1 段移到 exit 0 之前）
# ============================================================

MODDIR=${0%/*}
TMP_PATH=/data/adb/neozygisk

# --- pkgmask 段（不阻断）---
if [ -f "/sys/module/pkgmask/parameters/hidden_procs" ]; then
    echo "" > /sys/module/pkgmask/parameters/hidden_procs 2>/dev/null
fi

# --- Zygisk Next 冲突检测（安全网）---
if [ -d "/data/adb/modules/zygisksu" ] || [ -d "/data/adb/modules/zygisk-next" ] || [ -d "/data/adb/zygisk_next" ] || [ -d "/data/adb/zygisksu" ]; then
    echo "[neozygisk] Zygisk Next detected, abort" >> /dev/kmsg
    exit 0
fi

# --- NeoZygisk 初始化 ---
cd "$MODDIR"

# 复制 libzygisk.so 到运行时目录
if [ -f "$MODDIR/lib64/libzygisk.so" ]; then
    mkdir -p "$TMP_PATH/lib64"
    cp "$MODDIR/lib64/libzygisk.so" "$TMP_PATH/lib64/libzygisk.so"
    chcon u:object_r:system_file:s0 "$TMP_PATH/lib64/libzygisk.so" 2>/dev/null
fi

# 设置目录权限与 context
chmod 555 "$TMP_PATH"
chcon u:object_r:system_file:s0 "$TMP_PATH" 2>/dev/null

# 启动 Zygisk monitor（arm64，SM8750 纯64位）
"$MODDIR/bin/zygisk-ptrace64" monitor &
echo "[neozygisk] monitor started (arm64)" >> /dev/kmsg

# --- Per-App Props 配置初始化（插件硬编码路径，勿改文件名）---
# 持久化目录：/data/adb/susfs_env_guard/per_app_props/
PAP_DIR=/data/adb/susfs_env_guard/per_app_props
mkdir -p "$PAP_DIR" 2>/dev/null

# 创建插件硬编码的根目录标记文件
touch /.managed_by_skp_rezygisk 2>/dev/null
touch /.rezygisk-runtime 2>/dev/null
mkdir -p /.per-app-props 2>/dev/null

# 从持久化目录恢复配置到插件读取的临时位置
if [ -f "$PAP_DIR/features.conf" ]; then
    cp "$PAP_DIR/features.conf" /.per_app_props_features 2>/dev/null
fi
if [ -f "$PAP_DIR/target_package.conf" ]; then
    cp "$PAP_DIR/target_package.conf" /.per-app-props/target_package.conf 2>/dev/null
fi

# 首次启动：写入默认配置
if [ ! -f /.per_app_props_features ]; then
    printf 'version=1\ncpu=1\ngpu=1\ncpuinfo=1\ngpu_driver=mali\n' > /.per_app_props_features
    cp /.per_app_props_features "$PAP_DIR/features.conf" 2>/dev/null
fi
echo "[per_app_props] config initialized" >> /dev/kmsg

exit 0
#（注：内容由AI生成）
