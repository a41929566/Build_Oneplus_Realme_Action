#!/system/bin/sh
# SUSFS Env Guard v6.5 - 自检诊断
. "${0%/*}/lib_common.sh"

SUSFS_JSON="${SUSFS_JSON:-/data/adb/ksu/.susfs.json}"
ITEM_FILE="$RUN_DIR/selfcheck_items.tsv"
: > "$ITEM_FILE"

PASS=0; WARN=0; FAIL=0

decl_item() { printf '%s\t%s\n' "$1" "$2" >> "$ITEM_FILE"; }
ok(){  PASS=$((PASS+1)); decl_item ok   "$*"; }
wn(){  WARN=$((WARN+1)); echo "[WARN] $*"; decl_item warn "$*"; }
no(){  FAIL=$((FAIL+1)); echo "[FAIL] $*"; decl_item fail "$*"; }
ps_(){ PASS=$((PASS+1)); echo "[PASS] $*"; decl_item ok   "$*"; }

is_on() {
    case "$1" in 1|Y|y|true|TRUE|on|ON) return 0;; *) return 1;; esac
}

echo "===== SUSFS Env Guard v6.5 自检 $(date) ====="

echo "--- 文件完整性 ---"
for f in post-fs-data.sh service.sh module.prop sepolicy.rule \
         tools/lib_common.sh tools/props_spoof.sh tools/randomize.sh \
         tools/pkgmask_setup.sh tools/appops_setup.sh tools/daemon_loop.sh \
         tools/process_hide.sh tools/run.sh tools/susfs_fix.sh \
         tools/run_verify.sh tools/selfcheck.sh tools/log_rotate.sh \
         tools/cleanup.sh \
         config/spoof.conf.example config/bootconfig_spoof.txt \
         webroot/index.html; do
    if [ -f "$MODDIR/$f" ]; then
        ps_ "文件存在 $f"
    else
        no "缺失文件 $f"
    fi
done
[ -f "$CONF" ] && ps_ "配置文件存在 $CONF" || wn "配置文件缺失（用默认）"

echo "--- 属性伪装（安全区） ---"
init_feature_flags
PROPS_ON=$(get_config spoof_props_enabled 0)
HWID_ON=$(get_config spoof_hwid_enabled 0)
AID_ON=$(get_config spoof_android_id 0)

G=0
if [ "$PROPS_ON" = 1 ] || [ "$HWID_ON" = 1 ] || [ "$AID_ON" = 1 ]; then G=1; fi

if [ "$PROPS_ON" = 1 ]; then
    TMPF="$RUN_DIR/.sc_props"; : > "$TMPF"
    printf 'ro.debuggable:0\nro.secure:1\nro.build.tags:release-keys\nro.build.type:user\nsys.oem_unlock_allowed:0\n' | while IFS=: read -r p e; do
        a=$(getprop "$p")
        if [ "$a" = "$e" ]; then
            echo "P|属性 $p=$a" >> "$TMPF"
        else
            echo "F|属性 $p 当前=$a 期望=$e" >> "$TMPF"
        fi
    done
    while IFS='|' read -r st msg; do
        case "$st" in
            P) ps_ "$msg" ;;
            F) no "$msg" ;;
        esac
    done < "$TMPF"
    rm -f "$TMPF"
else
    wn "属性伪装未启用（显示真值属预期）"
fi

echo "--- 引导状态伪装（内核层） ---"
BC=$(cat /proc/bootconfig 2>/dev/null | tr '\n' ' ')
case "$BC" in
    *verifiedbootstate*green*) ps_ "bootconfig 已重定向为 green" ;;
    *) wn "bootconfig 未重定向（需执行 susfs_fix）" ;;
esac

if grep -q '"/proc/cmdline"' "$SUSFS_JSON" 2>/dev/null; then
    ps_ "cmdline 已重定向为 green"
else
    wn "cmdline 未重定向（需执行 susfs_fix）"
fi

VB_PROP=$(getprop ro.boot.verifiedbootstate)
ps_ "ro.boot.verifiedbootstate=$VB_PROP（属性层不改，交给内核重定向）"

echo "--- 硬件只读 ID ---"
if [ -f "$HWID_SYSFS/hwid_enabled" ]; then
    HE=$(cat "$HWID_SYSFS/hwid_enabled" 2>/dev/null)
    if [ "$HWID_ON" = 1 ] && is_on "$HE"; then
        HS=$(cat "$HWID_SYSFS/hwid_status" 2>/dev/null)
        if echo "$HS" | grep -q 'enabled=1' && echo "$HS" | grep -q 'hook_active=1'; then
            ps_ "hwid hook 已注册且参数已启用"
        else
            no "hwid hook 未就位（hwid_status=$HS）"
        fi
        if [ -f "$DATA_DIR/fake_profile.conf" ]; then
            ps_ "fake_profile.conf 已存在"
            . "$DATA_DIR/fake_profile.conf" 2>/dev/null
            if [ -n "$fake_cpu" ] && [ -n "$fake_soc" ]; then
                [ "$fake_cpu" = "$fake_soc" ] && ps_ "SoC == cpuinfo Serial（自洽）" \
                    || no "SoC != cpuinfo Serial（不自洽）"
            fi
            if [ -n "$fake_wmac" ] && [ -n "$fake_bmac" ]; then
                _w_oui=$(echo "$fake_wmac" | cut -d: -f1-3)
                _b_oui=$(echo "$fake_bmac" | cut -d: -f1-3)
                [ "$_w_oui" = "$_b_oui" ] && ps_ "WiFi 和 BT 同 OUI（自洽）" \
                    || no "WiFi OUI != BT OUI（不自洽）"
            fi
        else
            no "fake_profile.conf 不存在"
        fi
    else
        wn "hwid_spoof 未使能（enabled=$HE）"
    fi
else
    wn "内核无 hwid_spoof"
fi

echo "--- pkgmask ---"
if [ -d "$PKG_SYSFS" ]; then
    DU=$(cat "$PKG_SYSFS/deny_uids" 2>/dev/null)
    TP=$(cat "$PKG_SYSFS/target_paths" 2>/dev/null)
    [ -n "$DU" ] && ps_ "pkgmask deny_uids=$DU" || wn "pkgmask 无 deny_uids"
    [ -n "$TP" ] && ps_ "pkgmask target_paths 已配置" || wn "pkgmask 无 target_paths"

    HG=$(cat "$PKG_SYSFS/hook_getdents" 2>/dev/null)
    HD=$(cat "$PKG_SYSFS/hide_dirents" 2>/dev/null)
    if is_on "$HG" && is_on "$HD"; then
        ps_ "目录隐藏已启用（防零宽扫盘）"
    else
        no "hook_getdents=$HG hide_dirents=$HD 未同时启用"
    fi

    HP=$(cat "$PKG_SYSFS/hide_proc_enabled" 2>/dev/null)
    HN=$(cat "$PKG_SYSFS/hide_proc_names" 2>/dev/null)
    if is_on "$HP"; then
        ps_ "进程隐藏已启用：$HN"
    else
        wn "进程隐藏未启用"
    fi
else
    no "内核无 pkgmask"
fi

echo "--- SUSFS ---"
if [ -f "$SUSFS_JSON" ]; then
    ps_ "SUSFS .susfs.json 存在"
    if grep -q '"cmdline_or_bootconfig"' "$SUSFS_JSON" 2>/dev/null; then
        ps_ "cmdline_or_bootconfig 已配置"
    else
        wn "cmdline_or_bootconfig 未配置"
    fi
    if grep -q '"avc_log_spoofing": true' "$SUSFS_JSON" 2>/dev/null; then
        ps_ "AVC 日志伪装已启用"
    else
        wn "AVC 日志伪装未启用"
    fi
    if grep -q '"hide_sus_mnts_for_non_su_procs": true' "$SUSFS_JSON" 2>/dev/null; then
        ps_ "非 root 挂载隐藏已启用"
    else
        wn "非 root 挂载隐藏未启用"
    fi
    pc=$(grep -c '"path"' "$SUSFS_JSON" 2>/dev/null)
    [ "$pc" -gt 0 ] && ps_ "路径循环隐藏已注册 $pc 条" || wn "路径循环隐藏未注册"
else
    no "SUSFS .susfs.json 不存在（$SUSFS_JSON）"
fi

echo "--- 守护进程 ---"
if [ -f "$RUN_DIR/daemon.pid" ]; then
    DP=$(cat "$RUN_DIR/daemon.pid" 2>/dev/null)
    case "$DP" in
        ''|*[!0-9]*)
            wn "守护进程 pid 内容非法（$DP）"
            ;;
        *)
            if [ -d "/proc/$DP" ]; then
                ps_ "守护进程运行 PID=$DP"
            else
                wn "守护进程 pid=$DP 已退出（可能被系统杀过）"
            fi
            ;;
    esac
else
    wn "守护进程尚未启动（无 pid 文件）"
fi

echo "--- 启动历史 ---"
BOOT_HISTORY_FILE="$DATA_DIR/boot_history.txt"
if [ -f "$BOOT_HISTORY_FILE" ]; then
    BC=$(wc -l < "$BOOT_HISTORY_FILE" 2>/dev/null | tr -d ' ')
    case "$BC" in ''|*[!0-9]*) BC=0;; esac
    if [ "$BC" -ge 5 ]; then
        no "5 分钟内启动 $BC 次（阈值 5），模块可能已 disable"
    elif [ "$BC" -ge 3 ]; then
        wn "5 分钟内启动 $BC 次（阈值 5），注意不要频繁重启"
    else
        ps_ "启动历史正常（$BC 条记录）"
    fi
else
    ps_ "无启动历史文件（开机 5 分钟后自动清空）"
fi

echo "===== 汇总 PASS=$PASS WARN=$WARN FAIL=$FAIL ====="
cat > "$DATA_DIR/selfcheck_result.json" << EOF
{ "timestamp": "$(date +%s)", "pass": $PASS, "warn": $WARN, "fail": $FAIL,
  "global": "$G", "kernel": "$(uname -r)" }
EOF
chmod 644 "$DATA_DIR/selfcheck_result.json" 2>/dev/null
chmod 644 "$ITEM_FILE" 2>/dev/null
exit 0
