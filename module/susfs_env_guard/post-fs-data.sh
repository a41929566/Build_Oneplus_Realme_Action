#!/system/bin/sh
#===============================================================
#  post-fs-data.sh（NeoZygisk 整合版 v2）
#  1) pkgmask 配置（节点缺失不阻断）
#  2) Zygisk 冲突检测
#  3) NeoZygisk 启动（arm64）
#===============================================================

MODDIR=${0%/*}
cd "$MODDIR"

# --- pkgmask 配置持久化 ---
PKGMASK_DIR=/sys/module/pkgmask/parameters
PKGMASK_STATUS=$PKGMASK_DIR/status
PKGMASK_NAMES=$PKGMASK_DIR/hide_proc_names
PKGMASK_ENABLED=$PKGMASK_DIR/hide_proc_enabled
PKGMASK_RELOAD=$PKGMASK_DIR/reload

i=0
while [ ! -e "$PKGMASK_NAMES" ] && [ $i -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done

if [ -e "$PKGMASK_NAMES" ]; then
    if grep -q "stealth=1" "$PKGMASK_STATUS" 2>/dev/null; then
        echo "[pkgmask] already configured, skip" >> /dev/kmsg
    else
        echo 1 > "$PKGMASK_ENABLED"
        echo -n "!test12345" > "$PKGMASK_NAMES"
        echo 1 > "$PKGMASK_RELOAD"
        if grep -q "stealth=1" "$PKGMASK_STATUS" 2>/dev/null; then
            echo "[pkgmask] post-fs-data applied" >> /dev/kmsg
        else
            echo "[pkgmask] post-fs-data FAILED" >> /dev/kmsg
        fi
    fi
else
    echo "[pkgmask] parameter node missing, skip" >> /dev/kmsg
fi

# --- Zygisk 冲突检测 ---
if [ "$ZYGISK_ENABLED" ]; then
    echo "[neozygisk] ZYGISK_ENABLED set by Magisk, skip" >> /dev/kmsg
    exit 0
fi
for zydir in /data/adb/modules/zygisksu /data/adb/modules/zygisk-next; do
    if [ -d "$zydir" ] && [ ! -f "$zydir/disable" ]; then
        echo "[neozygisk] conflicting module: $zydir, abort" >> /dev/kmsg
        exit 0
    fi
done
for zydata in /data/adb/zygisk_next /data/adb/zygisksu /data/adb/rezygisk; do
    if [ -d "$zydata" ]; then
        echo "[neozygisk] conflicting runtime: $zydata, abort" >> /dev/kmsg
        exit 0
    fi
done
for zyscript in /data/adb/service.d/rezygisk.sh /data/adb/post-fs-data.d/zygisksu.sh; do
    if [ -f "$zyscript" ]; then
        echo "[neozygisk] conflicting script: $zyscript, abort" >> /dev/kmsg
        exit 0
    fi
done
if pgrep -f zygisk-ptrace64 > /dev/null 2>&1 || pgrep -f zygiskd64 > /dev/null 2>&1; then
    echo "[neozygisk] Zygisk process already running, skip" >> /dev/kmsg
    exit 0
fi

# --- NeoZygisk 文件存在性检查 ---
if [ ! -x "$MODDIR/bin/zygisk-ptrace64" ]; then
    echo "[neozygisk] bin/zygisk-ptrace64 missing or not executable" >> /dev/kmsg
    exit 0
fi
if [ ! -f "$MODDIR/bin/zygiskd64" ]; then
    echo "[neozygisk] bin/zygiskd64 missing" >> /dev/kmsg
fi
if [ ! -f "$MODDIR/lib64/libzygisk.so" ]; then
    echo "[neozygisk] lib64/libzygisk.so missing" >> /dev/kmsg
fi

# --- NeoZygisk 初始化 ---
TMP_PATH=/data/adb/neozygisk
rm -rf "$TMP_PATH" 2>/dev/null
mkdir -p "$TMP_PATH"

# 先复制 libzygisk.so 到运行时目录（在设置 555 之前）
if [ -f "$MODDIR/lib64/libzygisk.so" ]; then
    mkdir -p "$TMP_PATH/lib64"
    cp "$MODDIR/lib64/libzygisk.so" "$TMP_PATH/lib64/libzygisk.so"
    chcon u:object_r:system_file:s0 "$TMP_PATH/lib64/libzygisk.so" 2>/dev/null
fi

# 复制完成后再设置目录权限与 context
chmod 555 "$TMP_PATH"
chcon u:object_r:system_file:s0 "$TMP_PATH" 2>/dev/null

# 启动 Zygisk monitor（arm64，SM8750 纯64位）
"$MODDIR/bin/zygisk-ptrace64" monitor &
echo "[neozygisk] monitor started (arm64)" >> /dev/kmsg

exit 0
