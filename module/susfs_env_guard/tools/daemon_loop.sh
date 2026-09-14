#!/system/bin/sh
# SUSFS环境守护 v6.3 - 守护进程
# 职责：1) 消费 action.txt 动作  2) 聚合 status.json 供 WebUI 实时反馈
#       3) 全程容错，单点失败绝不退出
# 由 service.sh 以 setsid 后台启动，开机自启。

. "${0%/*}/lib_common.sh"

PKG="$PKG_SYSFS"
HWID="$HWID_SYSFS"
STATUS_FILE="$MODDIR/webroot/status.json"
PID_FILE="$RUN_DIR/daemon.pid"
mkdir -p "$MODDIR/webroot"
echo "$$" > "$PID_FILE"
trap 'rm -f "$PID_FILE"' EXIT

gprop() { getprop "$1" 2>/dev/null; }
catf() { cat "$1" 2>/dev/null; }

# ---------- 聚合状态 ----------
write_status() {
    local G aid fake_inc
    init_feature_flags
    G=0
    [ "$(get_config spoof_props_enabled 0)" = 1 ] && G=1
    [ "$(get_config spoof_hwid_enabled 0)" = 1 ] && G=1
    [ "$(get_config spoof_android_id 0)" = 1 ] && G=1
    . "$DATA_DIR/fake_profile.conf" 2>/dev/null

    # 属性
    local serial inc fp vb dbg tags oem model
    serial=$(gprop ro.serialno); inc=$(gprop ro.build.version.incremental)
    fp=$(gprop ro.build.fingerprint); vb=$(gprop ro.boot.verifiedbootstate)
    dbg=$(gprop ro.debuggable); tags=$(gprop ro.build.tags); oem=$(gprop sys.oem_unlock_allowed)
    model=$(gprop ro.product.model)

    # 硬件 ID（内核）
    local hwsup=0 hwen=0 hsoc hwcid hcpu hwmac hbmac
    if [ -f "$HWID/hwid_enabled" ]; then
        hwsup=1; hwen=$(catf "$HWID/hwid_enabled")
        local ks; ks=$(catf "$HWID/hwid_status")
        hwactive=$(printf '%s\n' "$ks" | sed -n 's/.*hook_active=\([01]\).*/\1/p')
        hwactive=${hwactive:-0}
        hsoc=$(echo "$ks" | sed -n 's/^soc_serial=//p')
        hwcid=$(echo "$ks" | sed -n 's/^cid=//p')
        hcpu=$(echo "$ks" | sed -n 's/^cpu_serial=//p')
        hwmac=$(echo "$ks" | sed -n 's/^wlan_mac=//p')
        hbmac=$(echo "$ks" | sed -n 's/^bt_mac=//p')
    fi
    local aidcur; aidcur=$(settings --user 0 get secure android_id 2>/dev/null)

    # pkgmask
    local pmsup=0 pmdeny pmpaths pmscope pmhproc pmhname pmstat
    if [ -d "$PKG" ] && [ -f "$PKG/reload" ]; then
        pmsup=1
        pmdeny=$(catf "$PKG/deny_uids"); pmpaths=$(catf "$PKG/target_paths")
        pmscope=$(catf "$PKG/scope_mode"); pmhproc=$(catf "$PKG/hide_proc_enabled")
        pmhname=$(catf "$PKG/hide_proc_names"); pmstat=$(catf "$PKG/status" | tr '\n' ';')
    fi

    # SUSFS / kernel
    local susver susstate
    susver=$(catf /sys/module/susfs/version)
    if [ -n "$susver" ]; then
        susstate="ready"
    elif [ -d /sys/module/susfs ] || [ -d /sys/module/ksu_susfs ]; then
        susstate="present"
        susver="present"
    else
        susstate="built_in_or_hidden"
        susver="built-in/hidden"
    fi
    local kver karch; kver=$(uname -r 2>/dev/null); karch=$(uname -m 2>/dev/null)

    # 自检结果
    local scp=0 scw=0 scf=0
    if [ -f "$DATA_DIR/selfcheck_result.json" ]; then
        scp=$(sed -n 's/.*"pass": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
        scw=$(sed -n 's/.*"warn": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
        scf=$(sed -n 's/.*"fail": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
    fi

    # 目标/隐藏列表（WebUI 展示当前到底配了什么）
    local tgts hides; tgts=$(get_config pkgmask_targets ""); hides=$(get_config pkgmask_hide_pkgs "")
    local identity_state; identity_state=$(catf "$DATA_DIR/identity_state")

    # JSON 转义（值里可能有特殊字符，统一用函数）
    jq_s() { echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

    local tmp="$STATUS_FILE.tmp"
    {
      echo "{"
      echo "  \"ts\": $(date +%s),"
      echo "  \"global\": \"$G\","
      echo "  \"features\": {\"props\":\"$(get_config spoof_props_enabled 0)\",\"android_id\":\"$(get_config spoof_android_id 0)\",\"hwid\":\"$(get_config spoof_hwid_enabled 0)\"},"
      echo "  \"identity_transaction\": \"$(jq_s "$identity_state")\","
      echo "  \"props\": {\"serial\":\"$(jq_s "$serial")\",\"fake_serial\":\"$(jq_s "$fake_serial")\",\"incremental\":\"$(jq_s "$inc")\",\"fake_inc\":\"$(jq_s "$fake_inc")\",\"fingerprint\":\"$(jq_s "$fp")\",\"vbstate\":\"$vb\",\"debuggable\":\"$dbg\",\"tags\":\"$tags\",\"oem\":\"$oem\",\"model\":\"$(jq_s "$model")\"},"
      echo "  \"hwid\": {\"supported\":\"$hwsup\",\"enabled\":\"$hwen\",\"hook_active\":\"$hwactive\",\"cur_aid\":\"$(jq_s "$aidcur")\",\"fake_aid\":\"$(jq_s "$fake_aid")\",\"soc\":\"$(jq_s "$hsoc")\",\"fake_soc\":\"$(jq_s "$fake_soc")\",\"cid\":\"$(jq_s "$hwcid")\",\"fake_cid\":\"$(jq_s "$fake_cid")\",\"cpu\":\"$(jq_s "$hcpu")\",\"wmac\":\"$(jq_s "$hwmac")\",\"fake_wmac\":\"$(jq_s "$fake_wmac")\",\"bmac\":\"$(jq_s "$hbmac")\",\"fake_bmac\":\"$(jq_s "$fake_bmac")\"},"
      echo "  \"pkgmask\": {\"supported\":\"$pmsup\",\"scope\":\"$(jq_s "$pmscope")\",\"deny_uids\":\"$(jq_s "$pmdeny")\",\"target_paths\":\"$(jq_s "$pmpaths")\",\"hide_proc\":\"$pmhproc\",\"hide_proc_names\":\"$(jq_s "$pmhname")\",\"status\":\"$(jq_s "$pmstat")\",\"targets\":\"$(jq_s "$tgts")\",\"hide_pkgs\":\"$(jq_s "$hides")\"},"
      echo "  \"susfs\": {\"version\":\"$(jq_s "$susver")\",\"state\":\"$susstate\"},"
      echo "  \"kernel\": {\"version\":\"$(jq_s "$kver")\",\"arch\":\"$karch\"},"
      echo "  \"selfcheck\": {\"pass\":\"${scp:-0}\",\"warn\":\"${scw:-0}\",\"fail\":\"${scf:-0}\"}"
      echo "}"
    } > "$tmp" 2>/dev/null && mv -f "$tmp" "$STATUS_FILE"
}

# ---------- 动作消费 ----------
handle_action() {
    local a; a=$(cat "$ACTION_FILE" 2>/dev/null); rm -f "$ACTION_FILE"
    [ -z "$a" ] && return
    log 2 "action: $a"
    case "$a" in
        props_on) set_config spoof_props_enabled 1; sh "$MODDIR/tools/props_spoof.sh" apply ;;
        props_off) set_config spoof_props_enabled 0; sh "$MODDIR/tools/props_spoof.sh" restore ;;
        android_on) set_config spoof_android_id 1; sh "$MODDIR/tools/randomize.sh" apply ;;
        android_off) set_config spoof_android_id 0; sh "$MODDIR/tools/randomize.sh" restore_aid; sh "$MODDIR/tools/randomize.sh" apply ;;
        spoof_on|spoof_off|randomize_all|restore_all)
            log 1 "global action rejected; use per-feature actions"
            ;;
        pkgmask_apply) sh "$MODDIR/tools/pkgmask_setup.sh" apply ;;
        pkgmask_restore) sh "$MODDIR/tools/pkgmask_setup.sh" restore ;;
        appops_apply) sh "$MODDIR/tools/appops_setup.sh" apply ;;
        selfcheck) sh "$MODDIR/tools/selfcheck.sh" > "$RUN_DIR/last_selfcheck.txt" 2>&1 ;;
        cleanup) sh "$MODDIR/tools/cleanup.sh" ;;
        hwid_on) set_config spoof_hwid_enabled 1; sh "$MODDIR/tools/randomize.sh" apply ;;
        hwid_off) set_config spoof_hwid_enabled 0; sh "$MODDIR/tools/randomize.sh" apply ;;
        hide_proc_add:*)
            local comm cur found="" item
            comm=$(echo "${a#hide_proc_add:}" | cut -c1-15)  # task->comm 最长15
            cur=$(catf "$PKG/hide_proc_names")
            # 去重
            for item in $(echo "$cur" | tr ',' ' '); do
                [ "$item" = "$comm" ] && found=1
            done
            [ -z "$found" ] && echo "${cur:+$cur,}$comm" > "$PKG/hide_proc_names" 2>/dev/null
            echo 1 > "$PKG/hide_proc_enabled" 2>/dev/null
            echo 1 > "$PKG/reload" 2>/dev/null
            ;;
        targets_set:*)
            # targets_set|<空格分隔的检测方包名>
            local list="${a#targets_set:}"
            set_config pkgmask_targets "$list"
            sh "$MODDIR/tools/pkgmask_setup.sh" apply
            sh "$MODDIR/tools/appops_setup.sh" apply
            ;;
        hidepkgs_set:*)
            local list="${a#hidepkgs_set:}"
            set_config pkgmask_hide_pkgs "$list"
            sh "$MODDIR/tools/pkgmask_setup.sh" apply
            ;;
        *) log 1 "unknown action: $a" ;;
    esac
    write_status
}

# ---------- 主循环（绝不退出） ----------
echo "=== daemon start $(date) ===" >> "$RUN_DIR/daemon.log"
LOOP=0
ACTIVE_LOOPS=0
IDLE=$(get_config daemon_interval_idle 15)
case "$IDLE" in ''|*[!0-9]*) IDLE=15;; [1-9]*) ;; *) IDLE=15;; esac
ACTIVE=$(get_config daemon_interval_active 1)
case "$ACTIVE" in ''|*[!0-9]*) ACTIVE=1;; [1-9]*) ;; *) ACTIVE=1;; esac
while true; do
    LOOP=$((LOOP+1))
    if [ -f "$ACTION_FILE" ]; then
        handle_action || true
        ACTIVE_LOOPS=15
    fi
    [ $((LOOP % 40)) -eq 0 ] && sh "$MODDIR/tools/log_rotate.sh" >/dev/null 2>&1 || true
    if [ "$ACTIVE_LOOPS" -gt 0 ]; then
        write_status || true
        ACTIVE_LOOPS=$((ACTIVE_LOOPS-1))
        sleep "$ACTIVE"
    else
        [ $((LOOP % 4)) -eq 0 ] && write_status || true
        sleep "$IDLE"
    fi
done
