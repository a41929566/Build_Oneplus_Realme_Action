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

if [ -f "$MODDIR/tools/device_model.sh" ]; then
    log_file "--> device_model.sh apply"
    sh "$MODDIR/tools/device_model.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- device_model.sh rc=$?"
fi

if [ -f "$MODDIR/tools/identity_ids.sh" ]; then
    log_file "--> identity_ids.sh apply"
    sh "$MODDIR/tools/identity_ids.sh" apply >> "$RUN_LOG" 2>&1
    log_file "<-- identity_ids.sh rc=$?"
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

# 日志轮转。
# 原先 log_rotate.sh 只被 daemon_loop.sh 的常驻循环调用（LOOP % 40 == 0），
# 但常驻 daemon 从来没有被启动过 —— run.sh 明确不常驻（见文末注释），
# WebUI 只跑 `daemon_loop.sh --once`，而 --once 分支在 handle_action 后直接
# exit，永远走不到那个循环。结果是 run/*.log 与 logs/*.log 永不轮转、
# 长期使用无限增长。这里在每次开机的收尾处补一次轮转。
if [ -f "$MODDIR/tools/log_rotate.sh" ]; then
    sh "$MODDIR/tools/log_rotate.sh" >/dev/null 2>&1
    log_file "log_rotate.sh done"
fi

log_file "=== run.sh done (no daemon, --once mode) ==="
# 不常驻 daemon：所有伪装已在上面一次性 apply
# WebUI 通过 shExec 实时读 sysfs，点按钮时跑 daemon_loop.sh --once
#（注：内容由AI生成）
