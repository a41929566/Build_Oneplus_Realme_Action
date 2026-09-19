#!/system/bin/sh
# SUSFS Env Guard v6.5 - run.sh（统一入口）
. "${0%/*}/lib_common.sh"

RUN_LOG="$RUN_DIR/run.log"
log_file() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$RUN_LOG"; }

log_file "=== run.sh start ==="

i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 60 ]; do
    sleep 2; i=$((i+1))
done
log_file "boot_completed after ~$((i*2))s"

j=0
while ! service check settings >/dev/null 2>&1 || ! service check appops >/dev/null 2>&1; do
    sleep 2; j=$((j+1))
    if [ $j -gt 30 ]; then
        log_file "Timeout waiting for settings/appops service"
        break
    fi
done
log_file "system services ready"

if [ -f "$MODDIR/tools/susfs_fix.sh" ]; then
    log_file "--> susfs_fix.sh apply"
    sh "$MODDIR/tools/susfs_fix.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- susfs_fix.sh rc=$?"
fi

if [ -f "$MODDIR/tools/props_spoof.sh" ]; then
    log_file "--> props_spoof.sh apply"
    sh "$MODDIR/tools/props_spoof.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- props_spoof.sh rc=$?"
fi

if [ -f "$MODDIR/tools/randomize.sh" ]; then
    log_file "--> randomize.sh apply"
    sh "$MODDIR/tools/randomize.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- randomize.sh rc=$?"
fi

if [ -f "$MODDIR/tools/pkgmask_setup.sh" ]; then
    log_file "--> pkgmask_setup.sh apply"
    sh "$MODDIR/tools/pkgmask_setup.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- pkgmask_setup.sh rc=$?"
fi

if [ -f "$MODDIR/tools/process_hide.sh" ]; then
    log_file "--> process_hide.sh apply"
    sh "$MODDIR/tools/process_hide.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- process_hide.sh rc=$?"
fi

if [ -f "$MODDIR/tools/appops_setup.sh" ]; then
    log_file "--> appops_setup.sh apply"
    sh "$MODDIR/tools/appops_setup.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- appops_setup.sh rc=$?"
fi

# 杀掉旧 daemon（如果有）
if [ -f "$RUN_DIR/daemon.pid" ]; then
    OLD_PID=$(cat "$RUN_DIR/daemon.pid" 2>/dev/null)
    case "$OLD_PID" in
        ''|*[!0-9]*) ;;
        *) kill "$OLD_PID" 2>/dev/null || true ;;
    esac
    sleep 1
fi

if [ -f "$MODDIR/tools/selfcheck.sh" ]; then
    log_file "--> selfcheck.sh"
    sh "$MODDIR/tools/selfcheck.sh" > "$RUN_DIR/selfcheck.txt" 2>&1
    log_file "<-- selfcheck.sh rc=$?"
fi

log_file "=== run.sh done (no daemon, --once mode) ==="
# 不常驻 daemon：所有伪装已在上面一次性 apply
# WebUI 通过 shExec 实时读 sysfs，点按钮时跑 daemon_loop.sh --once
#（注：内容由AI生成）
