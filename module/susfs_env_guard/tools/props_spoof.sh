#!/system/bin/sh
# SUSFS Env Guard v6.5 - props_spoof.sh（属性伪装 · 安全版）
#
# 【设计原则 - 三条红线】
#   ① 引导状态属性（ro.boot.verifiedbootstate 等）
#      → zygote 前修改必卡黄字，改由 SUSFS 内核层重定向
#      → L2 段在 boot_completed==1 后同步属性层
#   ② 设备唯一值属性（ro.serialno / ro.build.fingerprint 等）
#      → 内核 hwid_spoof 在 read(2) 层拦截，属性层也要同步写
#      → v6.5: 新增 fingerprint / display.id / incremental 三个属性
#   ③ 用户态可改的 root 痕迹属性
#      → ro.debuggable / ro.secure / ro.build.tags 等
#
# 【执行时机】由 service.sh 在开机 10 秒后调用
#
# 【用法】props_spoof.sh {apply|restore|status}

. "${0%/*}/lib_common.sh"

ORIG="${BACKUP_DIR}/props_orig.conf"
L2_MARKER="${DATA_DIR}/L2_applied"
L0L1_MARKER="${DATA_DIR}/L0L1_applied"

# ============================================================
# 锁状态 / root 痕迹属性（安全区）
# ⚠️ 严禁添加任何 ro.boot.* 属性！会卡黄字
# ============================================================
LOCK_PROPS="ro.debuggable=0
ro.secure=1
ro.adb.secure=1
sys.oem_unlock_allowed=0
ro.build.tags=release-keys
ro.build.type=user
ro.build.selinux=1
init.svc.adbd=stopped"

# 其他安全属性
MISC_PROPS="net.hostname"

# ============================================================
# v6.5: 系统版本属性（开机 10 秒后写入）
# 这些是 ro.* 属性，必须用 resetprop -n 写入（不通知 init）
# ============================================================
_build_props_from_conf() {
    local enabled
    enabled=$(get_config SPOOF_BUILD_PROPS 0)
    [ "$enabled" = "1" ] || return 0

    local fp did inc
    fp=$(get_config PROP_FINGERPRINT "")
    did=$(get_config PROP_DISPLAY_ID "")
    inc=$(get_config PROP_INCREMENTAL "")

    [ -n "$fp" ]  && rp_set ro.build.fingerprint "$fp"
    [ -n "$did" ] && rp_set ro.build.display.id "$did"
    [ -n "$inc" ] && rp_set ro.build.version.incremental "$inc"
    [ -n "$fp" ]  && rp_set ro.system.build.fingerprint "$fp"
    [ -n "$did" ] && rp_set ro.build.display.id.show "$did"

    log 2 "props_spoof L3: build props applied (fp/did/inc)"
}

# 备份原始值（仅一次）
backup_orig() {
    [ -f "$ORIG" ] && return 0
    {
        echo "$LOCK_PROPS" | while IFS='=' read -r p v; do
            [ -n "$p" ] && echo "${p}=$(getprop "$p")"
        done
        for p in $MISC_PROPS; do
            echo "${p}=$(getprop "$p")"
        done
        # v6.5: 备份 build props 真值
        for p in ro.build.fingerprint ro.build.display.id ro.build.version.incremental ro.system.build.fingerprint ro.build.display.id.show; do
            echo "${p}=$(getprop "$p")"
        done
    } > "$ORIG"
}

# ---------- apply ----------
do_apply() {
    init_feature_flags
    backup_orig
    local on; on=$(get_config spoof_props_enabled 0)
    [ "$on" != "1" ] && { do_restore; return; }

    # L0 锁状态 / root 痕迹（安全区属性）
    echo "$LOCK_PROPS" | while IFS='=' read -r p v; do
        [ -n "$p" ] && rp_set "$p" "$v"
    done

    # L1 其他安全属性
    rp_set net.hostname "localhost" 2>/dev/null

    cat /proc/sys/kernel/random/boot_id > "$L0L1_MARKER" 2>/dev/null

    # L2 引导状态属性层同步（boot_completed==1 才执行）
    local boot_ok; boot_ok=$(getprop sys.boot_completed 2>/dev/null)
    if [ "$boot_ok" = "1" ]; then
        rp_set ro.boot.verifiedbootstate    "green"
        rp_set ro.boot.flash.locked         "1"
        rp_set ro.boot.vbmeta.device_state  "locked"
        rp_set ro.boot.veritymode           "enforcing"
        rp_set ro.boot.selinux              "enforcing"
        if [ -n "$(getprop vendor.boot.verifiedbootstate)" ]; then
            rp_set vendor.boot.verifiedbootstate    "green"
            rp_set vendor.boot.vbmeta.device_state  "locked"
            rp_set vendor.boot.flash.locked         "1"
        fi
        cat /proc/sys/kernel/random/boot_id > "$L2_MARKER" 2>/dev/null
        log 2 "props_spoof L2: boot-completed, applied ro.boot.* spoof"

        # v6.5: L3 系统版本属性（必须在 boot_completed 后）
        _build_props_from_conf
    else
        log 1 "props_spoof L2: sys.boot_completed != 1, skip ro.boot.* spoof (would brick device)"
    fi

    log 2 "props_spoof applied (safe mode: lock-state + build props)"
    echo "PROPS_SPOOF=OK"
}

# ---------- restore ----------
do_restore() {
    if [ -f "$L0L1_MARKER" ]; then
        _prev=$(cat "$L0L1_MARKER" 2>/dev/null)
        _cur=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
        if [ -n "$_prev" ] && [ "$_prev" = "$_cur" ]; then
            for pair in $LOCK_PROPS; do rp_del "${pair%%=*}"; done
            for p in $MISC_PROPS; do rp_del "$p"; done
            log 2 "props_spoof L0/L1: restored (same boot session)"
        fi
        rm -f "$L0L1_MARKER"
    fi

    if [ -f "$L2_MARKER" ]; then
        _prev_boot=$(cat "$L2_MARKER" 2>/dev/null)
        _cur_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
        if [ -n "$_prev_boot" ] && [ "$_prev_boot" = "$_cur_boot" ]; then
            for p in ro.boot.verifiedbootstate ro.boot.flash.locked \
                     ro.boot.vbmeta.device_state ro.boot.veritymode \
                     ro.boot.selinux \
                     vendor.boot.verifiedbootstate \
                     vendor.boot.vbmeta.device_state \
                     vendor.boot.flash.locked; do
                rp_del "$p"
            done
            # v6.5: 还原 build props 真值
            local v
            for p in ro.build.fingerprint ro.build.display.id ro.build.version.incremental ro.system.build.fingerprint ro.build.display.id.show; do
                v=$(orig_val "$p")
                [ -n "$v" ] && rp_set "$p" "$v"
            done
            log 2 "props_spoof L2+L3: restored (same boot session)"
        fi
        rm -f "$L2_MARKER"
    fi

    log 2 "props_spoof restored (overrides deleted)"
}

# ---------- status ----------
do_status() {
    echo "{"
    echo "  \"enabled\": \"$(get_config spoof_props_enabled 0)\","
    echo "  \"vbstate\": \"$(getprop ro.boot.verifiedbootstate)\","
    echo "  \"debuggable\": \"$(getprop ro.debuggable)\","
    echo "  \"secure\": \"$(getprop ro.secure)\","
    echo "  \"tags\": \"$(getprop ro.build.tags)\","
    echo "  \"type\": \"$(getprop ro.build.type)\","
    echo "  \"oem_unlock\": \"$(getprop sys.oem_unlock_allowed)\","
    echo "  \"adbd\": \"$(getprop init.svc.adbd)\","
    echo "  \"fingerprint\": \"$(getprop ro.build.fingerprint)\","
    echo "  \"display_id\": \"$(getprop ro.build.display.id)\","
    echo "  \"incremental\": \"$(getprop ro.build.version.incremental)\""
    echo "}"
}

case "$1" in
    apply)   do_apply ;;
    restore) do_restore ;;
    status)  do_status ;;
    *) echo "usage: $0 {apply|restore|status}" ;;
esac
