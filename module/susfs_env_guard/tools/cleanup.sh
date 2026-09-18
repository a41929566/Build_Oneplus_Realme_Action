#!/system/bin/sh
# SUSFS环境守护 v6.4 - 临时文件清理（不删除活动配置和系统日志）
. "${0%/*}/lib_common.sh"

# 1) /data/local/tmp 下本模块的临时文件
rm -f /data/local/tmp/susfs_* 2>/dev/null

# 2) shell 历史（避免留下 resetprop/echo sysfs 命令痕迹）
rm -f /data/local/tmp/.bash_history /data/local/tmp/.sh_history 2>/dev/null
for h in /data/adb/ksu/.history /data/adb/ap/.history; do [ -f "$h" ] && : > "$h"; done

# 3) 旧轮转日志截断（保留当前 guard.log，不删活动日志）
for f in "$RUN_DIR"/*.log.1 "$DATA_DIR/logs"/*.log.1; do [ -f "$f" ] && rm -f "$f"; done

# 4) KSU / LSPosed / Zygisk 日志清理（这些是检测方常扫的残留）
rm -rf /data/adb/ksu/log 2>/dev/null
rm -rf /data/adb/ksud/log 2>/dev/null
rm -rf /data/adb/lspd/log 2>/dev/null
rm -rf /data/adb/lspd/log.old 2>/dev/null
rm -rf /data/adb/modules/zygisk-next/log 2>/dev/null
rm -rf /data/adb/modules/zygisk-assistant/log 2>/dev/null
rm -rf /data/adb/modules/rezygisk/log 2>/dev/null
rm -rf /data/adb/modules/zygisksu/log 2>/dev/null
rm -rf /data/adb/modules/playintegrityfix/log 2>/dev/null
rm -rf /data/adb/modules/teesimulator/log 2>/dev/null
rm -rf /data/adb/modules/teesimulator-rs/log 2>/dev/null

# 5) 模块安装残留（update 目录是 Magisk/KSU 安装模块时留下的临时目录）
find /data/adb/modules -maxdepth 2 -type d -name update -exec rm -rf {} + 2>/dev/null

# 6) LSPosed 的缓存（无日志但留指纹）
rm -rf /data/adb/lspd/config/cache 2>/dev/null
rm -rf /data/adb/lspd/config/log 2>/dev/null

# 7) Zygisk 的 unshare 残留
rm -rf /data/adb/modules/zygisk-next/.zygisk 2>/dev/null
rm -rf /data/adb/modules/rezygisk/.zygisk 2>/dev/null

# 8) 本模块自己的临时写入痕迹
rm -f "$RUN_DIR/.sc_props" 2>/dev/null
rm -f "$RUN_DIR/.probe.tmp" 2>/dev/null
rm -f "$RUN_DIR/.sus_paths.tmp" 2>/dev/null
rm -f "$DATA_DIR/.bh.tmp" 2>/dev/null

# 注意：不删除 fake_profile / spoof.conf / backup 数据（功能必需，删除反而制造不一致）
log 2 "cleanup done (tmp/history/ksu-log/lspd-log/zygisk-log/module-update cleared, active config kept)"
echo "CLEANUP_OK"
