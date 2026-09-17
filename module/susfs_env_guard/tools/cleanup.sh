#!/system/bin/sh
# SUSFS环境守护 v6.3 - 临时文件清理（不删除活动配置和系统日志）
. "${0%/*}/lib_common.sh"

# 1) /data/local/tmp 下本模块的临时文件
rm -f /data/local/tmp/susfs_* 2>/dev/null

# 2) shell 历史（避免留下 resetprop/echo sysfs 命令痕迹）
rm -f /data/local/tmp/.bash_history /data/local/tmp/.sh_history 2>/dev/null
for h in /data/adb/ksu/.history /data/adb/ap/.history; do [ -f "$h" ] && : > "$h"; done

# 3) 旧轮转日志截断（保留当前 guard.log，不删活动日志）
for f in "$RUN_DIR"/*.log.1 "$DATA_DIR/logs"/*.log.1; do [ -f "$f" ] && rm -f "$f"; done

# 注意：不删除 fake_profile / spoof.conf / backup 数据（功能必需，删除反而制造不一致）
log 2 "cleanup done (tmp/history cleared, active config kept)"
echo "CLEANUP_OK"
