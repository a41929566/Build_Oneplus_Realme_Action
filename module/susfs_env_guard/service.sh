#!/system/bin/sh
# SUSFS环境守护 v6.3 - service.sh（late_start service 阶段）
# 注意：ro.* 属性伪装已全部前移到 post-fs-data.sh，这里不再 resetprop，
#       避免 zygote 已固化真值后再改导致 JVM/getprop 三通道不一致。
MODDIR=${0%/*}
. "$MODDIR/tools/lib_common.sh"

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$DATA_DIR/logs" "$RUN_DIR"
[ -f "$CONF" ] || cp -f "$MODDIR/config/spoof.conf.example" "$CONF"
init_feature_flags

echo "=== service.sh start $(date) ===" > "$RUN_DIR/service.log"

# 等待 /data 与系统就绪（android_id / pm / appops 需要 system_server）
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 60 ]; do
    sleep 2; i=$((i+1))
done
sleep 3
log 2 "boot_completed after ~$((i*2))s"

# 1) 硬件层 android_id（settings 需 system_server，只能在此）+ 复核内核 hwid
sh "$MODDIR/tools/randomize.sh" apply >> "$RUN_DIR/service.log" 2>&1

# 2) pkgmask 真 sysfs 配置（需要 pm 取 uid，故放此阶段）
sh "$MODDIR/tools/pkgmask_setup.sh" apply >> "$RUN_DIR/service.log" 2>&1

# 3) AppOps 撤销检测方“查询应用列表”
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

# 5) 初次自检（守护进程启动后再检查，避免误报“未运行”）
sleep 1
sh "$MODDIR/tools/selfcheck.sh" > "$RUN_DIR/first_selfcheck.txt" 2>&1

echo "=== service.sh done $(date) ===" >> "$RUN_DIR/service.log"
