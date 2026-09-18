#!/system/bin/sh
# SUSFS Env Guard v6.4 - service.sh（late_start service 阶段）
# 【安全区】等待系统稳定后，调用 run.sh 执行所有伪装逻辑
#
# 为什么延后到开机 10 秒后：
#   1) 一加 Bootloader 在 zygote 前会校验 ro.boot.verifiedbootstate，
#      此阶段之前修改属性会触发完整性校验失败，无限重启（卡黄字）
#   2) settings / appops 服务需要 system_server 就绪后才能调用
#   3) kprobe 挂载延后可以避免系统启动早期的进程调度冲突
#
# v6.4-opt2: 时间窗口启动计数器（避免开发阶段频繁刷机误禁）

. "${0%/*}/tools/lib_common.sh"

mkdir -p "$RUN_DIR" 2>/dev/null

# ============================================================
# v6.4-opt2: 时间窗口启动计数器
#
# 逻辑：
#   - boot_history.txt 记录最近 N 次启动的 epoch 秒时间戳
#   - 每次启动：过滤掉 5 分钟之外的旧记录，追加当前时间戳
#   - 若 5 分钟内有 >= 5 次启动 → 判定为启动循环，自动 disable
#   - 开机 300 秒后系统稳定，清空历史文件
#
# 好处：
#   - 正常使用：每次开机只产生 1 条记录，永远不触发禁用
#   - 频繁调试：5 分钟内刷 5 次才会禁用，不会一刷就禁
# ============================================================
BOOT_HISTORY_FILE="$DATA_DIR/boot_history.txt"
WINDOW=300
LIMIT=5

NOW=$(date +%s 2>/dev/null)
case "$NOW" in ''|*[!0-9]*) NOW=0;; esac

_tmp="$DATA_DIR/.bh.tmp"
: > "$_tmp"

if [ -f "$BOOT_HISTORY_FILE" ]; then
    while IFS= read -r ts; do
        case "$ts" in
            ''|*[!0-9]*) continue ;;
        esac
        if [ $((NOW - ts)) -lt "$WINDOW" ]; then
            echo "$ts" >> "$_tmp"
        fi
    done < "$BOOT_HISTORY_FILE"
fi

echo "$NOW" >> "$_tmp"
mv -f "$_tmp" "$BOOT_HISTORY_FILE" 2>/dev/null

count=$(wc -l < "$BOOT_HISTORY_FILE" 2>/dev/null | tr -d ' ')
case "$count" in ''|*[!0-9]*) count=0;; esac

if [ "$count" -ge "$LIMIT" ]; then
    touch "$MODDIR/disable" 2>/dev/null
    {
        echo "=== SUSFS Env Guard auto-disabled at $(date) ==="
        echo "$WINDOW 秒内启动 $count 次（阈值 $LIMIT），判定为启动循环。"
        echo ""
        echo "排查方法："
        echo "  1) 查看 /data/adb/modules/susfs_env_guard/run/boot.log"
        echo "  2) 查看 /data/adb/modules/susfs_env_guard/run/run.log"
        echo "  3) 确认 spoof.conf 里没有写入任何 ro.boot.* 属性"
        echo "  4) 确认内核 hwid_spoof 惰性化生效（不会在 init 阶段注册 kretprobe）"
        echo ""
        echo "修复后手动恢复："
        echo "  rm /data/adb/modules/susfs_env_guard/disable"
        echo "  rm /data/adb/susfs_env_guard/boot_history.txt"
    } > "$DATA_DIR/disabled.log" 2>/dev/null
    log 0 "service.sh: boot count=$count >= $LIMIT in ${WINDOW}s, auto-disabled"
    exit 0
fi

log 2 "service.sh start, boot_in_window=$count"

# 后台执行，不阻塞开机
(
    sleep 10
    sh "$MODDIR/tools/run.sh" > "$RUN_DIR/boot.log" 2>&1

    # 开机 300 秒后系统稳定，清空启动历史
    (
        sleep 300
        rm -f "$BOOT_HISTORY_FILE" 2>/dev/null
        log 2 "boot_history cleared after 300s stable"
    ) &
) &

exit 0
