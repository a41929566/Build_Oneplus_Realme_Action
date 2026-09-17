#!/system/bin/sh
# SUSFS Env Guard v3.0 - post-fs-data.sh（zygote 前执行）
# 【安全区】只做文件准备，绝不修改任何系统属性
#
# 核心原则：
#   1) 此阶段只做文件准备，不碰任何 ro.* 属性
#   2) 引导状态伪装由 SUSFS 的 cmdline_or_bootconfig 在内核层完成
#   3) 属性三连延后到 service.sh（开机 10 秒后）
#   4) cmdline/bootconfig 伪装文件由 susfs_fix.sh 在 service 阶段生成
#      此阶段只清理过期文件，避免 zygote 前操作内核

. "${0%/*}/tools/lib_common.sh"

# 应用本模块 SELinux 规则
if [ -f "$MODDIR/sepolicy.rule" ]; then
    "$MAGISKPOLICY" --apply "$MODDIR/sepolicy.rule" 2>/dev/null
fi

# 清理上一轮的伪装文件（避免残留格式错误的内容被误引用）
# 真正的伪装文件在 service.sh → run.sh → susfs_fix.sh 里生成
rm -f "$MODDIR/config/cmdline_spoof.txt" "$MODDIR/config/cmdline_fake.txt" 2>/dev/null

# 所有属性伪装、硬件 ID、pkgmask、进程隐藏全部延后到 service.sh
exit 0
