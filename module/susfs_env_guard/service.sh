#!/system/bin/sh
# SUSFS环境守护 v6.3 - service.sh（late_start service 阶段）
# 所有属性伪装 + 内核 hwid + android_id 全部在此阶段执行（系统启动完成后）
# 避免在 post-fs-data（zygote 前）修改 ro.* 属性或挂 vfs_read hook 导致系统重启
MODDIR=${0%/*}
. "$MODDIR/tools/lib_common.sh"

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$DATA_DIR/logs" "$RUN_DIR"
[ -f "$CONF" ] || cp -f "$MODDIR/config/spoof.conf.example" "$CONF"
init_feature_flags

echo "=== service.sh start $(date) ===" > "$RUN_DIR/service.log"

# 等待 /data 与系统就绪（android_id / pm / appops 需要 system_server）
i=0
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 60 ]; do
    sleep 2; i=$((i+1))
done
sleep 5
log 2 "boot_completed after ~$((i*2))s"

# 额外等待 settings 和 appops 服务真正可用
j=0
while ! service check settings >/dev/null 2>&1 || ! service check appops >/dev/null 2>&1; do
    sleep 2; j=$((j+1))
    if [ $j -gt 30 ]; then
        log 2 "Timeout waiting for settings/appops service"
        break
    fi
done
log 2 "system services ready"

# 0) 属性伪装（延后到系统启动完成后执行，避免 zygote 前改属性导致重启）
# sh "$MODDIR/tools/props_spoof.sh" apply >> "$RUN_DIR/service.log" 2>&1

# 1) 硬件层 android_id（settings 需 system_server，只能在此）+ 内核 hwid
sh "$MODDIR/tools/randomize.sh" apply >> "$RUN_DIR/service.log" 2>&1

# 2) pkgmask 真 sysfs 配置（需要 pm 取 uid，故放此阶段）
sh "$MODDIR/tools/pkgmask_setup.sh" apply >> "$RUN_DIR/service.log" 2>&1

# 3) AppOps 撤销检测方"查询应用列表"
sh "$MODDIR/tools/appops_setup.sh" apply >> "$RUN_DIR/service.log" 2>&1

# 4) 启动守护进程（单实例，setsid 脱离）
if [ -f "$RUN_DIR/daemon.pid" ]; then
    OLD_PID=$(cat "$RUN_DIR/daemon.pid" 2>/dev/null)
    case "$OLD_PID" in
        ''|*[!0-9]*) ;;
        *) kill "$OLD_PID" 2>/dev/null || true ;;
    esac
fi
sleep 1
setsid sh "$MODDIR/tools/daemon_loop.sh" >> "$RUN_DIR/daemon.boot.log" 2>&1 &

# 5) 初次自检（守护进程启动后再检查，避免误报"未运行"）
sleep 1
sh "$MODDIR/tools/selfcheck.sh" > "$RUN_DIR/first_selfcheck.txt" 2>&1

echo "=== service.sh done $(date) ===" >> "$RUN_DIR/service.log"
