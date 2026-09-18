#!/system/bin/sh
# SUSFS环境守护 v6.4 - 守护进程
# 职责：1) 消费 action.txt 动作 2) 聚合 status.json 3) 全程容错
#
# v6.4 优化：
#   - 支持 --once：处理一次 action + 刷新 status 后退出（WebUI 即时反馈用）
#   - 主循环每秒检查 action.txt，缩短响应延迟
#   - 新增 save_hide 动作：A/B 一次性保存，避免两次写入互相覆盖
#   - 新增 restore_all 动作：恢复全部真值（hwid + props）
#   - idle 写 status 间隔缩短为 3 秒

. "${0%/*}/lib_common.sh"

ONCE_MODE=false
[ "$1" = "--once" ] && ONCE_MODE=true

PKG="$PKG_SYSFS"
HWID="$HWID_SYSFS"
STATUS_FILE="$MODDIR/webroot/status.json"
PID_FILE="$RUN_DIR/daemon.pid"
USER_PATHS_FILE="$DATA_DIR/user_hidden_paths.txt"
mkdir -p "$MODDIR/webroot"

if [ "$ONCE_MODE" = "false" ]; then
    echo "$$" > "$PID_FILE"
    trap 'rm -f "$PID_FILE"' EXIT
fi

LAST_ACTION=""
LAST_ACTION_TIME=0
gprop() { getprop "$1" 2>/dev/null; }
catf() { cat "$1" 2>/dev/null; }

jq_s() { echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }
jq_s_raw() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# ---------- SUSFS 检测 ----------
detect_susfs() {
    local out=""

    local bc_kernel; bc_kernel=$(catf /proc/bootconfig | tr '\n' ' ')
    local cl_kernel; cl_kernel=$(catf /proc/cmdline | tr '\n' ' ')

    local bc_ok=0
    case "$bc_kernel" in *verifiedbootstate*green*) bc_ok=$((bc_ok+1));; esac
    case "$bc_kernel" in *vbmeta.device_state*locked*) bc_ok=$((bc_ok+1));; esac
    if [ "$bc_ok" -ge 2 ]; then
        out="${out}bootconfig伪装|ok|green/locked|green/locked|/proc/bootconfig 已重定向到伪装值\n"
    else
        out="${out}bootconfig伪装|fail|${bc_kernel:-空}|green/locked|SUSFS cmdline_or_bootconfig 未生效\n"
    fi

    if grep -q '"/proc/cmdline"' "$SUSFS_JSON" 2>/dev/null; then
        out="${out}cmdline重定向|ok|已配置|green|/proc/cmdline 对普通进程已重定向（root 视角豁免属正常）\n"
    else
        out="${out}cmdline重定向|warn|未配置|green|open_redirect 未写入 .susfs.json\n"
    fi

    local p1 p2 p3
    p1=$(gprop ro.boot.verifiedbootstate)
    p2=$(gprop ro.boot.vbmeta.device_state)
    p3=$(gprop ro.boot.flash.locked)
    local cur_vals="${p1:-空}/${p2:-空}/${p3:-空}"
    if [ "$p1" = "green" ] && [ "$p2" = "locked" ] && [ "$p3" = "1" ]; then
        out="${out}prop三连|ok|$cur_vals|green/locked/1|属性层已直接伪装\n"
    elif [ "$bc_ok" -ge 2 ] || [ "$(case "$cl_kernel" in *verifiedbootstate=green*) echo 1;; *) echo 0;; esac)" = "1" ]; then
        out="${out}prop三连|ok|属性层=$cur_vals + 内核重定向 green|green/locked/1|应用读取走内核重定向\n"
    else
        out="${out}prop三连|warn|属性层=$cur_vals 内核未重定向|green/locked/1|请点「一键修复」\n"
    fi

    if grep -q '"avc_log_spoofing": true' "$SUSFS_JSON" 2>/dev/null; then
        out="${out}AVC日志伪装|ok|已启用|已启用|免疫 AVC 日志审计\n"
    else
        out="${out}AVC日志伪装|warn|未启用|已启用|内核可能不支持\n"
    fi

    if grep -q '"hide_sus_mnts_for_non_su_procs": true' "$SUSFS_JSON" 2>/dev/null; then
        out="${out}挂载隐藏|ok|已启用|已启用|非root进程看不到 sus 挂载\n"
    else
        out="${out}挂载隐藏|warn|未启用|已启用|内核可能不支持\n"
    fi

    local path_count
    path_count=$(catf "$SUSFS_JSON" | grep -c '"path"' 2>/dev/null)
    path_count=${path_count:-0}
    if [ "$path_count" -gt 0 ]; then
        out="${out}路径循环隐藏|ok|$path_count 条|>0|已在 .susfs.json 注册\n"
    else
        out="${out}路径循环隐藏|warn|0 条|>0|未注册 sus_path\n"
    fi

    local KS
    KS=$(command -v ksu_susfs 2>/dev/null || \
         for p in /data/adb/ksu/bin/ksu_susfs /data/adb/ksud/bin/ksu_susfs; do
             [ -x "$p" ] && { echo "$p"; break; }
         done)
    if [ -n "$KS" ]; then
        out="${out}ksu_susfs工具|ok|$KS|存在|就绪\n"
    else
        out="${out}ksu_susfs工具|fail|未找到|存在|内核未编译 SUSFS\n"
    fi

    printf '%s' "$out"
}

# ---------- 进程列表 ----------
list_procs() {
    local first=1
    echo -n "["
    if command -v ps >/dev/null 2>&1; then
        ps -A -o PID,UID,NAME 2>/dev/null | tail -n +2 | \
        while read -r pid uid name; do
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            [ -z "$name" ] && continue
            [ "$first" = 1 ] && first=0 || echo -n ","
            printf '{"pid":"%s","uid":"%s","comm":"%s"}' \
                "$pid" "$uid" "$(jq_s "$name")"
        done
    else
        for d in /proc/[0-9]*; do
            [ -d "$d" ] || continue
            local pid=${d#/proc/}
            local comm; comm=$(catf "$d/comm")
            [ -z "$comm" ] && continue
            local uid; uid=$(stat -c %u "$d" 2>/dev/null)
            [ "$first" = 1 ] && first=0 || echo -n ","
            printf '{"pid":"%s","uid":"%s","comm":"%s"}' \
                "$pid" "$uid" "$(jq_s "$comm")"
        done
    fi
    echo -n "]"
}

list_user_paths() {
    [ -f "$USER_PATHS_FILE" ] || return 0
    grep -v '^[[:space:]]*#' "$USER_PATHS_FILE" 2>/dev/null | grep -v '^[[:space:]]*$'
}

# ---------- 聚合状态 ----------
write_status() {
    local G
    init_feature_flags
    G=0
    [ "$(get_config spoof_props_enabled 0)" = 1 ] && G=1
    [ "$(get_config spoof_hwid_enabled 0)" = 1 ] && G=1
    [ "$(get_config spoof_android_id 0)" = 1 ] && G=1
    . "$DATA_DIR/fake_profile.conf" 2>/dev/null

    local serial inc fp vb dbg tags oem model
    serial=$(gprop ro.serialno); inc=$(gprop ro.build.version.incremental)
    fp=$(gprop ro.build.fingerprint); vb=$(gprop ro.boot.verifiedbootstate)
    dbg=$(gprop ro.debuggable); tags=$(gprop ro.build.tags); oem=$(gprop sys.oem_unlock_allowed)
    model=$(gprop ro.product.model)

    local hwsup=0 hwen=0 hwactive=0 hsoc hwcid hcpu hwmac hbmac
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
    local hwid_uids; hwid_uids=$(catf "$HWID/hwid_uids")

    local pmsup=0 pmdeny pmpaths pmscope pmhproc pmhname pmstat
    if [ -d "$PKG" ] && [ -f "$PKG/reload" ]; then
        pmsup=1
        pmdeny=$(catf "$PKG/deny_uids"); pmpaths=$(catf "$PKG/target_paths")
        pmscope=$(catf "$PKG/scope_mode"); pmhproc=$(catf "$PKG/hide_proc_enabled")
        pmhname=$(catf "$PKG/hide_proc_names"); pmstat=$(catf "$PKG/status" | tr '\n' ';')
    fi

    local susver susstate
    susver=$(catf /sys/module/susfs/version)
    if [ -n "$susver" ]; then
        susstate="ready"
    elif [ -d /sys/module/susfs ] || [ -d /sys/module/ksu_susfs ]; then
        susstate="present"; susver="present"
    else
        susstate="built_in_or_hidden"; susver="built-in/hidden"
    fi
    local kver karch; kver=$(uname -r 2>/dev/null); karch=$(uname -m 2>/dev/null)

    local scp=0 scw=0 scf=0
    if [ -f "$DATA_DIR/selfcheck_result.json" ]; then
        scp=$(sed -n 's/.*"pass": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
        scw=$(sed -n 's/.*"warn": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
        scf=$(sed -n 's/.*"fail": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
    fi

    local tgts hides; tgts=$(get_config pkgmask_targets ""); hides=$(get_config pkgmask_hide_pkgs "")
    local identity_state; identity_state=$(catf "$DATA_DIR/identity_state")
    local susfs_check; susfs_check=$(detect_susfs)
    local verify; verify=$(catf "$RUN_DIR/verify_cache.json"); [ -z "$verify" ] && verify="[]"
    local procs; procs=$(catf "$RUN_DIR/procs_cache.json"); [ -z "$procs" ] && procs="[]"

    local user_paths
    user_paths=$(list_user_paths | tr '\n' '|' | sed 's/|$//')

    local sus_paths_json
    sus_paths_json=$(catf "$SUSFS_JSON" | grep -o '"/[^"]*"' | tr '\n' '|' | sed 's/|$//')

    local sc_items
    sc_items=$(awk -F'\t' '
        BEGIN{printf "["}
        {
            if(NR>1) printf ","
            gsub(/\\/,"\\\\",$2)
            gsub(/"/,"\\\"",$2)
            printf "{\"st\":\"%s\",\"msg\":\"%s\"}",$1,$2
        }
        END{printf "]"}
    ' "$RUN_DIR/selfcheck_items.tsv" 2>/dev/null)
    [ -z "$sc_items" ] && sc_items="[]"

    local tmp="$STATUS_FILE.tmp"
    {
      echo "{"
      echo "  \"ts\": $(date +%s),"
      echo "  \"global\": \"$G\","
      echo "  \"last_action\": \"$(jq_s "$LAST_ACTION")\","
      echo "  \"last_action_time\": ${LAST_ACTION_TIME:-0},"
      echo "  \"features\": {\"props\":\"$(get_config spoof_props_enabled 0)\",\"android_id\":\"$(get_config spoof_android_id 0)\",\"hwid\":\"$(get_config spoof_hwid_enabled 0)\",\"pkgmask\":\"$(get_config spoof_pkgmask_enabled 0)\",\"prochide\":\"$(get_config spoof_process_hide_enabled 0)\",\"suspath\":\"$(get_config SUSFS_PATH_HIDE 0)\"},"
      echo "  \"identity_transaction\": \"$(jq_s "$identity_state")\","
      echo "  \"props\": {\"serial\":\"$(jq_s "$serial")\",\"fake_serial\":\"$(jq_s "$fake_serial")\",\"incremental\":\"$(jq_s "$inc")\",\"fake_inc\":\"$(jq_s "$fake_inc")\",\"fingerprint\":\"$(jq_s "$fp")\",\"vbstate\":\"$vb\",\"debuggable\":\"$dbg\",\"tags\":\"$tags\",\"oem\":\"$oem\",\"model\":\"$(jq_s "$model")\"},"
      echo "  \"hwid\": {\"supported\":\"$hwsup\",\"enabled\":\"$hwen\",\"hook_active\":\"$hwactive\",\"uids\":\"$(jq_s "$hwid_uids")\",\"cur_aid\":\"$(jq_s "$aidcur")\",\"fake_aid\":\"$(jq_s "$fake_aid")\",\"soc\":\"$(jq_s "$hsoc")\",\"fake_soc\":\"$(jq_s "$fake_soc")\",\"cid\":\"$(jq_s "$hwcid")\",\"fake_cid\":\"$(jq_s "$fake_cid")\",\"cpu\":\"$(jq_s "$hcpu")\",\"fake_cpu\":\"$(jq_s "$fake_cpu")\",\"wmac\":\"$(jq_s "$hwmac")\",\"fake_wmac\":\"$(jq_s "$fake_wmac")\",\"bmac\":\"$(jq_s "$hbmac")\",\"fake_bmac\":\"$(jq_s "$fake_bmac")\"},"
      echo "  \"pkgmask\": {\"supported\":\"$pmsup\",\"scope\":\"$(jq_s "$pmscope")\",\"deny_uids\":\"$(jq_s "$pmdeny")\",\"target_paths\":\"$(jq_s "$pmpaths")\",\"hide_proc\":\"$pmhproc\",\"hide_proc_names\":\"$(jq_s "$pmhname")\",\"status\":\"$(jq_s "$pmstat")\",\"targets\":\"$(jq_s "$tgts")\",\"hide_pkgs\":\"$(jq_s "$hides")\"},"
      echo "  \"susfs\": {\"version\":\"$(jq_s "$susver")\",\"state\":\"$susstate\",\"check\":\"$(jq_s_raw "$susfs_check")\"},"
      echo "  \"sus_path\": {\"user\":\"$(jq_s "$user_paths")\",\"registered\":\"$(jq_s "$sus_paths_json")\"},"
      echo "  \"kernel\": {\"version\":\"$(jq_s "$kver")\",\"arch\":\"$karch\"},"
      echo "  \"selfcheck\": {\"pass\":\"${scp:-0}\",\"warn\":\"${scw:-0}\",\"fail\":\"${scf:-0}\",\"items\":$sc_items},"
      echo "  \"verify\": $verify,"
      echo "  \"procs\": $procs"
      echo "}"
    } > "$tmp" 2>/dev/null && mv -f "$tmp" "$STATUS_FILE"
}

# ---------- 动作消费 ----------
handle_action() {
    local a; a=$(cat "$ACTION_FILE" 2>/dev/null); rm -f "$ACTION_FILE"
    [ -z "$a" ] && return
    LAST_ACTION="$a"
    LAST_ACTION_TIME=$(date +%s)
    log 2 "action: $a"
    case "$a" in
        props_on) set_config spoof_props_enabled 1; sh "$MODDIR/tools/props_spoof.sh" apply ;;
        props_off) set_config spoof_props_enabled 0; sh "$MODDIR/tools/props_spoof.sh" restore ;;
        android_on) set_config spoof_android_id 1; sh "$MODDIR/tools/randomize.sh" apply ;;
        android_off) set_config spoof_android_id 0; sh "$MODDIR/tools/randomize.sh" restore; sh "$MODDIR/tools/randomize.sh" apply ;;
        hwid_on) set_config spoof_hwid_enabled 1; sh "$MODDIR/tools/randomize.sh" apply ;;
        hwid_off) set_config spoof_hwid_enabled 0; sh "$MODDIR/tools/randomize.sh" apply ;;
        # v6.4-opt2: 恢复全部真值（hwid + props），供 WebUI 一键恢复按钮调用
        restore_all)
            sh "$MODDIR/tools/randomize.sh" restore
            sh "$MODDIR/tools/props_spoof.sh" restore
            set_config spoof_hwid_enabled 0
            set_config spoof_props_enabled 0
            ;;
        id_apps_set:*)
            local pkgs="${a#id_apps_set:}" uids="" p u
            for p in $(echo "$pkgs" | tr ',' ' '); do
                [ -z "$p" ] && continue
                u=$(pkg_uid "$p")
                [ -n "$u" ] && uids="${uids:+$uids,}$u"
            done
            echo "$uids" > "$HWID/hwid_uids" 2>/dev/null
            echo 1 > "$HWID/hwid_reload" 2>/dev/null
            ;;
        susfs_fix)
            sh "$MODDIR/tools/susfs_fix.sh" apply
            ;;
        susfs_check) : ;;
        pkgmask_apply) sh "$MODDIR/tools/pkgmask_setup.sh" apply ;;
        pkgmask_restore) sh "$MODDIR/tools/pkgmask_setup.sh" restore ;;
        appops_apply) sh "$MODDIR/tools/appops_setup.sh" apply ;;
        targets_set:*)
            local list="${a#targets_set:}"
            set_config pkgmask_targets "$list"
            sh "$MODDIR/tools/pkgmask_setup.sh" apply
            sh "$MODDIR/tools/appops_setup.sh" apply
            sh "$MODDIR/tools/run_verify.sh" "$list" >/dev/null 2>&1
            ;;
        hidepkgs_set:*)
            local list="${a#hidepkgs_set:}"
            set_config pkgmask_hide_pkgs "$list"
            sh "$MODDIR/tools/pkgmask_setup.sh" apply
            local tgts; tgts=$(get_config pkgmask_targets "")
            sh "$MODDIR/tools/run_verify.sh" "$tgts" >/dev/null 2>&1
            ;;
        save_hide:*)
            local payload="${a#save_hide:}"
            local listA="${payload%%|*}"
            local listB="${payload#*|}"
            local A_space; A_space=$(echo "$listA" | tr ',' ' ')
            local B_space; B_space=$(echo "$listB" | tr ',' ' ')
            set_config pkgmask_targets "$A_space"
            set_config pkgmask_hide_pkgs "$B_space"
            sh "$MODDIR/tools/pkgmask_setup.sh" apply
            sh "$MODDIR/tools/appops_setup.sh" apply
            sh "$MODDIR/tools/run_verify.sh" "$A_space" >/dev/null 2>&1
            ;;
        prochide_list)
            list_procs > "$RUN_DIR/procs_cache.json" 2>/dev/null
            ;;
        hide_proc_add:*|prochide_add:*)
            local comm cur found="" item
            comm=$(echo "${a#*:}" | cut -c1-15)
            cur=$(catf "$PKG/hide_proc_names")
            for item in $(echo "$cur" | tr ',' ' '); do
                [ "$item" = "$comm" ] && found=1
            done
            [ -z "$found" ] && echo "${cur:+$cur,}$comm" > "$PKG/hide_proc_names" 2>/dev/null
            echo 1 > "$PKG/hide_proc_enabled" 2>/dev/null
            echo 1 > "$PKG/reload" 2>/dev/null
            ;;
        prochide_del:*)
            local comm cur new item
            comm=$(echo "${a#prochide_del:}" | cut -c1-15)
            cur=$(catf "$PKG/hide_proc_names")
            new=""
            for item in $(echo "$cur" | tr ',' ' '); do
                [ "$item" = "$comm" ] && continue
                new="${new:+$new,}$item"
            done
            echo "$new" > "$PKG/hide_proc_names" 2>/dev/null
            echo 1 > "$PKG/reload" 2>/dev/null
            ;;
        suspath_add:*)
            local path="${a#suspath_add:}"
            [ -z "$path" ] && return
            touch "$USER_PATHS_FILE" 2>/dev/null
            if ! grep -qxF "$path" "$USER_PATHS_FILE" 2>/dev/null; then
                echo "$path" >> "$USER_PATHS_FILE"
                log 2 "user path added: $path"
            fi
            local KS2
            KS2=$(command -v ksu_susfs 2>/dev/null || \
                  for p in /data/adb/ksu/bin/ksu_susfs /data/adb/ksud/bin/ksu_susfs; do
                      [ -x "$p" ] && { echo "$p"; break; }
                  done)
            if [ -n "$KS2" ] && [ -e "$path" ]; then
                "$KS2" config sus_path add "$path" --loop 2>/dev/null
            fi
            ;;
        suspath_del:*)
            local path="${a#suspath_del:}"
            [ -z "$path" ] && return
            if [ -f "$USER_PATHS_FILE" ]; then
                grep -vxF "$path" "$USER_PATHS_FILE" > "${USER_PATHS_FILE}.tmp" 2>/dev/null
                mv -f "${USER_PATHS_FILE}.tmp" "$USER_PATHS_FILE" 2>/dev/null
                log 2 "user path removed: $path"
            fi
            ;;
        suspath_list) : ;;
        selfcheck) sh "$MODDIR/tools/selfcheck.sh" > "$RUN_DIR/last_selfcheck.txt" 2>&1 ;;
        cleanup) sh "$MODDIR/tools/cleanup.sh" ;;
        *) log 1 "unknown action: $a" ;;
    esac
    write_status
}

# ---------- 一次性模式 ----------
if [ "$ONCE_MODE" = "true" ]; then
    handle_action || true
    exit 0
fi

# ---------- 主循环 ----------
echo "=== daemon start $(date) ===" >> "$RUN_DIR/daemon.log"
echo "kworker/u16:99" > "/proc/$$/comm" 2>/dev/null
echo "DEBUG: pid=$$ ppid=$PPID comm=$(cat /proc/$$/comm 2>/dev/null)" >> "$RUN_DIR/daemon.log"

if [ -w /sys/module/pkgmask/parameters/hide_proc_names ]; then
    _hpn=/sys/module/pkgmask/parameters/hide_proc_names
    _cur=$(cat "$_hpn" 2>/dev/null)
    case ",$_cur," in
        *",kcompactd99,"*) ;;
        *)
            echo "${_cur:+$_cur,}kcompactd99" > "$_hpn" 2>/dev/null
            echo 1 > /sys/module/pkgmask/parameters/hide_proc_enabled 2>/dev/null
            echo 1 > /sys/module/pkgmask/parameters/reload 2>/dev/null
            ;;
    esac
fi

LOOP=0
ACTIVE_LOOPS=0
STATUS_TICK=0
STATUS_INTERVAL_IDLE=3
while true; do
    LOOP=$((LOOP+1))

    if [ -f "$ACTION_FILE" ]; then
        handle_action || true
        ACTIVE_LOOPS=10
        STATUS_TICK=0
    fi

    if [ "$ACTIVE_LOOPS" -gt 0 ]; then
        write_status || true
        ACTIVE_LOOPS=$((ACTIVE_LOOPS-1))
        STATUS_TICK=0
    else
        STATUS_TICK=$((STATUS_TICK+1))
        if [ "$STATUS_TICK" -ge "$STATUS_INTERVAL_IDLE" ]; then
            write_status || true
            STATUS_TICK=0
        fi
    fi

    [ $((LOOP % 40)) -eq 0 ] && sh "$MODDIR/tools/log_rotate.sh" >/dev/null 2>&1 || true

    sleep 1
done
