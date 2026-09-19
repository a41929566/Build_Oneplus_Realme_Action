#!/system/bin/sh
# pkgmask 配置持久化 —— 每次开机自动 apply

MODDIR=${0%/*}
PKGMASK_DIR=/sys/module/pkgmask/parameters
PKGMASK_STATUS=$PKGMASK_DIR/status
PKGMASK_NAMES=$PKGMASK_DIR/hide_proc_names
PKGMASK_ENABLED=$PKGMASK_DIR/hide_proc_enabled
PKGMASK_RELOAD=$PKGMASK_DIR/reload

# 等参数节点就绪（最多 5 秒）
i=0
while [ ! -e "$PKGMASK_NAMES" ] && [ $i -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done

if [ ! -e "$PKGMASK_NAMES" ]; then
    echo "[pkgmask] parameter node missing" >> /dev/kmsg
    exit 1
fi

# 幂等：已配置就跳过
if grep -q "stealth=1" "$PKGMASK_STATUS" 2>/dev/null; then
    echo "[pkgmask] already configured, skip" >> /dev/kmsg
    exit 0
fi

# apply 配置
echo 1 > "$PKGMASK_ENABLED"
echo -n "!test12345" > "$PKGMASK_NAMES"
echo 1 > "$PKGMASK_RELOAD"

# 验证
if grep -q "stealth=1" "$PKGMASK_STATUS" 2>/dev/null; then
    echo "[pkgmask] post-fs-data applied" >> /dev/kmsg
else
    echo "[pkgmask] post-fs-data FAILED, status: $(cat $PKGMASK_STATUS)" >> /dev/kmsg
fi
#（注：内容由AI生成）
