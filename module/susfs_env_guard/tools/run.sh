#!/system/bin/sh
# SUSFS Env Guard v6.4 - run.sh（统一入口）
# 按顺序执行所有伪装逻辑，每个子脚本独立容错

. "${0%/*}/lib_common.sh"

RUN_LOG="$RUN_DIR/run.log"
log_file() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$RUN_LOG"; }

log_file "=== run.sh start ==="

# ---------- 1. 等待系统启动完成 ----------
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 60 ]; do
    sleep 2; i=$((i+1))
done
log_file "boot_completed after ~$((i*2))s"

# ---------- 2. 等待 settings / appops 服务就绪 ----------
j=0
while ! service check settings >/dev/null 2>&1 || ! service check appops >/dev/null 2>&1; do
    sleep 2; j=$((j+1))
    if [ $j -gt 30 ]; then
        log_file "Timeout waiting for settings/appops service"
        break
    fi
done
log_file "system services ready"

# ---------- 3. SUSFS 内核重定向 ----------
if [ -f "$MODDIR/tools/susfs_fix.sh" ]; then
    log_file "--> susfs_fix.sh apply"
    sh "$MODDIR/tools/susfs_fix.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- susfs_fix.sh rc=$?"
fi

# ---------- 4. 属性伪装（安全版） ----------
if [ -f "$MODDIR/tools/props_spoof.sh" ]; then
    log_file "--> props_spoof.sh apply"
    sh "$MODDIR/tools/props_spoof.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- props_spoof.sh rc=$?"
fi

# ---------- 5. 硬件 ID 内核拦截 ----------
if [ -f "$MODDIR/tools/randomize.sh" ]; then
    log_file "--> randomize.sh apply"
    sh "$MODDIR/tools/randomize.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- randomize.sh rc=$?"
fi

# ---------- 6. 应用隐藏（pkgmask） ----------
if [ -f "$MODDIR/tools/pkgmask_setup.sh" ]; then
    log_file "--> pkgmask_setup.sh apply"
    sh "$MODDIR/tools/pkgmask_setup.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- pkgmask_setup.sh rc=$?"
fi

# ---------- 7. 进程隐藏（内核层） ----------
if [ -f "$MODDIR/tools/process_hide.sh" ]; then
    log_file "--> process_hide.sh apply"
    sh "$MODDIR/tools/process_hide.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- process_hide.sh rc=$?"
fi

# ---------- 8. AppOps 撤销 ----------
if [ -f "$MODDIR/tools/appops_setup.sh" ]; then
    log_file "--> appops_setup.sh apply"
    sh "$MODDIR/tools/appops_setup.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- appops_setup.sh rc=$?"
fi

# ---------- 9. 自检并写状态文件 ----------
if [ -f "$MODDIR/tools/selfcheck.sh" ]; then
    log_file "--> selfcheck.sh"
    sh "$MODDIR/tools/selfcheck.sh" > "$RUN_DIR/selfcheck.txt" 2>&1
    log_file "<-- selfcheck.sh rc=$?"
fi

# ---------- 10. 启动守护进程（单实例）----------
# v6.4: setsid 在部分 Android sh 下静默失败，改用 nohup
if [ -f "$MODDIR/tools/daemon_loop.sh" ]; then
    if [ -f "$RUN_DIR/daemon.pid" ]; then
        OLD_PID=$(cat "$RUN_DIR/daemon.pid" 2>/dev/null)
        case "$OLD_PID" in
            ''|*[!0-9]*) ;;
            *) kill "$OLD_PID" 2>/dev/null || true ;;
        esac
        sleep 1
    fi
    nohup sh "$MODDIR/tools/daemon_loop.sh" >> "$RUN_DIR/daemon.boot.log" 2>&1 &
    log_file "daemon_loop.sh started (nohup)"
fi

log_file "=== run.sh done ==="
exit 0
