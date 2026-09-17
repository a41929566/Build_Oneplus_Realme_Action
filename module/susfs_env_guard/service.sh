#!/system/bin/sh
# SUSFS Env Guard v3.0 - service.sh（late_start service 阶段）
# 【安全区】等待系统稳定后，调用 run.sh 执行所有伪装逻辑
#
# 为什么延后到开机 10 秒后：
#   1) 一加 Bootloader 在 zygote 前会校验 ro.boot.verifiedbootstate，
#      此阶段之前修改属性会触发完整性校验失败，无限重启（卡黄字）
#   2) settings / appops 服务需要 system_server 就绪后才能调用
#   3) kprobe 挂载延后可以避免系统启动早期的进程调度冲突

. "${0%/*}/tools/lib_common.sh"

mkdir -p "$RUN_DIR" 2>/dev/null

# 后台执行，不阻塞开机
(
    sleep 10
    sh "$MODDIR/tools/run.sh" > "$RUN_DIR/boot.log" 2>&1
) &

exit 0
