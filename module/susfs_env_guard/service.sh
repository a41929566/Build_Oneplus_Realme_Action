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
# v6.4-opt1: 增加启动计数器，连续多次启动异常自动 disable 模块

. "${0%/*}/tools/lib_common.sh"

mkdir -p "$RUN_DIR" 2>/dev/null

# ============================================================
# v6.4-opt1: 失败降级保护
#
# 逻辑：
#   - 每次 service.sh 运行 boot_count+1
#   - 若 boot_count > 3（即第 4 次开机）→ 判定模块引发异常，自动 disable
#   - 若本次启动后 120 秒内系统仍正常 → 重置计数器为 0
#
# 效果：
#   即使模块配置错误导致卡黄字，最多刷 4 次之后模块自动禁用，用户能进系统修
# ============================================================
BOOT_COUNT_FILE="$DATA_DIR/boot_count"
count=$(cat "$BOOT_COUNT_FILE" 2>/dev/null || echo 0)
case "$count" in ''|*[!0-9]*) count=0;; esac
count=$((count+1))
echo "$count" > "$BOOT_COUNT_FILE" 2>/dev/null

if [ "$count" -gt 3 ]; then
    # 自动禁用：KSU/Magisk 看到 disable 文件后会跳过本模块
    touch "$MODDIR/disable" 2>/dev/null
    {
        echo "=== SUSFS Env Guard auto-disabled at $(date) ==="
        echo "boot_count=$count exceeded limit (3)"
        echo "last_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
        echo "kernel=$(uname -r 2>/dev/null)"
        echo ""
        echo "该模块被自动禁用，因为连续多次开机计数超过阈值。"
        echo "排查方法："
        echo "  1) 查看 /data/adb/modules/susfs_env_guard/run/boot.log"
        echo "  2) 查看 /data/adb/modules/susfs_env_guard/run/run.log"
        echo "  3) 确认 spoof.conf 没有写入 ro.boot.* 属性"
        echo "修复后手动删除 disable 文件并重启："
        echo "  rm /data/adb/modules/susfs_env_guard/disable"
    } > "$DATA_DIR/disabled.log" 2>/dev/null
    log 0 "boot_count=$count > 3, module auto-disabled"
    exit 0
fi

log 2 "service.sh start, boot_count=$count"

# 后台执行，不阻塞开机
(
    sleep 10
    sh "$MODDIR/tools/run.sh" > "$RUN_DIR/boot.log" 2>&1

    # 若 120 秒后计数器没有继续增长（即系统稳定运行），重置计数器
    # 这表示本次启动成功，不再视为异常
    (
        sleep 120
        _cur=$(cat "$BOOT_COUNT_FILE" 2>/dev/null || echo 0)
        case "$_cur" in ''|*[!0-9]*) _cur=0;; esac
        # 只有当前值还是本次启动的值时才重置（避免覆盖其他进程的写入）
        if [ "$_cur" = "$count" ]; then
            echo 0 > "$BOOT_COUNT_FILE" 2>/dev/null
            log 2 "boot_count reset to 0 after 120s stable"
        fi
    ) &
) &

exit 0
