#!/system/bin/sh
# SUSFS Env Guard v3.0 - props_spoof.sh（属性伪装 · 安全版）
#
# 【设计原则 - 三条红线，绝对不能碰】
#   ① 引导状态属性（ro.boot.verifiedbootstate 等）
#      → 一加 Bootloader 会在 zygote 前校验，改了必卡黄字无限重启
#      → 引导状态伪装改由 SUSFS 的 cmdline_or_bootconfig 在内核层重定向
#      → 【例外】L2 段（见下方 do_apply）会在 sys.boot_completed == 1
#        之后同步属性层，此时 Bootloader 校验已完成，可安全修改。
#        目的：让属性层与内核层 cmdline 重定向保持一致，
#        抗「应用同时读属性 + /proc/cmdline 交叉验证」的检测手法。
#   ② 设备唯一值属性（ro.serialno / ro.build.fingerprint 等）
#      → 内核 hwid_spoof 已在 read(2) 返回路径等长替换，属性层再改会不一致
#      → 保持真机属性不动，让内核层去骗应用层
#   ③ 用户态可改的"锁状态/root 痕迹"属性（本脚本只管这一类）
#      → ro.debuggable / ro.secure / ro.build.tags 等
#
# 【执行时机】由 service.sh 在开机 10 秒后调用（避开早期完整性校验窗口）
#
# 【用法】props_spoof.sh {apply|restore|status}

. "${0%/*}/lib_common.sh"

ORIG="${BACKUP_DIR}/props_orig.conf"
L2_MARKER="${DATA_DIR}/L2_applied"
L0L1_MARKER="${DATA_DIR}/L0L1_applied"

# ============================================================
# 锁状态 / root 痕迹属性（安全区，可以放心改）
#
# ⚠️ LOCK_PROPS 里严禁添加任何 ro.boot.* 属性！
#    历史教训：在 zygote 前修改 ro.boot.verifiedbootstate 导致一加
#    设备 Bootloader 完整性校验失败，无限重启（卡黄字）。
#
#    引导状态属性由 L2 段单独处理（见下方 do_apply），L2 只在
#    sys.boot_completed == 1 时执行，此时校验已完成，可安全修改。
# ============================================================
LOCK_PROPS="ro.debuggable=0
ro.secure=1
ro.adb.secure=1
sys.oem_unlock_allowed=0
ro.build.tags=release-keys
ro.build.type=user
ro.build.selinux=1
init.svc.adbd=stopped"

# 其他安全属性（非硬件唯一值）
MISC_PROPS="net.hostname"

# ---------- 备份原始值（仅一次，绝不覆盖真值） ----------
backup_orig() {
    [ -f "$ORIG" ] && return 0
    {
        echo "$LOCK_PROPS" | while IFS='=' read -r p v; do
            [ -n "$p" ] && echo "${p}=$(getprop "$p")"
        done
        for p in $MISC_PROPS; do
            echo "${p}=$(getprop "$p")"
        done
    } > "$ORIG"
}
orig_val() { grep "^$1=" "$ORIG" 2>/dev/null | head -1 | cut -d= -f2-; }

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

    # 标记 L0/L1 已应用（写入当前 boot_id），供 do_restore 判断
    # 是否应删除真值。防止 spoof_props_enabled=0 时每次开机删掉
    # init 写入的真实属性值。
    cat /proc/sys/kernel/random/boot_id > "$L0L1_MARKER" 2>/dev/null

    # L2 引导状态属性层同步（与 SUSFS 内核重定向保持一致）
    #
    # ⚠️ 安全守卫：L2 修改的是 ro.boot.* 属性，一加 Bootloader 会在
    #    zygote 前校验这些值。若在 sys.boot_completed != 1 时修改，
    #    会触发完整性校验失败 → 无限重启（卡黄字）。
    #
    #    守卫必须放在这里（而不是只在 service.sh 里 sleep 10），原因：
    #      - daemon_loop.sh 的 props_on 分支会调用本脚本
    #      - WebUI 可能在开机早期触发 props_on
    #      - uninstall.sh 的 restore 也会走 do_restore
    #    只有放在 do_apply 内部才能拦住所有调用路径。
    #
    #    执行成功后将当前 boot_id 写入 $L2_MARKER，
    #    do_restore 只在 marker 存在且 boot_id 匹配时才删除 ro.boot.*，
    #    防止误删 init/Bootloader 写入的真实值。
    local boot_ok; boot_ok=$(getprop sys.boot_completed 2>/dev/null)
    if [ "$boot_ok" = "1" ]; then
        rp_set ro.boot.verifiedbootstate    "green"
        rp_set ro.boot.flash.locked         "1"
        rp_set ro.boot.vbmeta.device_state  "locked"
        rp_set ro.boot.veritymode           "enforcing"
        rp_set ro.boot.selinux              "enforcing"
        # vendor 命名空间镜像（部分一加机型检测方读 vendor.boot.*）
        # 只在属性存在时才设置，避免在不支持的机型上制造脏属性
        if [ -n "$(getprop vendor.boot.verifiedbootstate)" ]; then
            rp_set vendor.boot.verifiedbootstate    "green"
            rp_set vendor.boot.vbmeta.device_state  "locked"
            rp_set vendor.boot.flash.locked         "1"
        fi
        cat /proc/sys/kernel/random/boot_id > "$L2_MARKER" 2>/dev/null
        log 2 "props_spoof L2: boot-completed, applied ro.boot.* spoof"
    else
        log 1 "props_spoof L2: sys.boot_completed != 1, skip ro.boot.* spoof (would brick device)"
    fi

    log 2 "props_spoof applied (safe mode: lock-state props only)"
    echo "PROPS_SPOOF=OK"
}

# ---------- restore：删除覆盖，回落真值 ----------
do_restore() {
    # L0/L1 还原 —— 只在「本 boot session 内确实 apply 过」时才删
    # 防止 spoof_props_enabled=0 时每次开机删掉 init 写入的真值
    if [ -f "$L0L1_MARKER" ]; then
        _prev=$(cat "$L0L1_MARKER" 2>/dev/null)
        _cur=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
        if [ -n "$_prev" ] && [ "$_prev" = "$_cur" ]; then
            for pair in $LOCK_PROPS; do rp_del "${pair%%=*}"; done
            for p in $MISC_PROPS; do rp_del "$p"; done
            log 2 "props_spoof L0/L1: restored (same boot session)"
        else
            log 2 "props_spoof L0/L1: stale marker from previous boot, init already restored real values"
        fi
        rm -f "$L0L1_MARKER"
    else
        log 2 "props_spoof L0/L1: no marker, skip delete (keep real values)"
    fi

    # L2 引导状态属性还原 —— 只在「本 boot session 内确实 apply 过」时才删
    #
    # ⚠️ 为什么需要这个守卫：
    #   do_apply 开头有 [ "$on" != "1" ] && { do_restore; return; }
    #   即「未启用」时也会走 restore 路径。run.sh 每次开机都会调 apply。
    #   如果没有守卫，spoof_props_enabled=0 的用户每次开机都会执行
    #   rp_del ro.boot.verifiedbootstate 等 —— 删除的却是 init/Bootloader
    #   写入的真实值 → 属性被删空 → 行为不可预测。
    #
    #   而 marker 里记录 boot_id 是为了跨重启场景：
    #   重启后属性已被 init 重置为真实值，此时若 marker 还在，
    #   直接 rp_del 同样会误删真实值。只有同一 boot session 才删。
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
            log 2 "props_spoof L2: restored (same boot session)"
        else
            log 2 "props_spoof L2: stale marker from previous boot, init already restored real values"
        fi
        rm -f "$L2_MARKER"
    else
        log 2 "props_spoof L2: no marker, skip ro.boot.* delete (keep real values)"
    fi

    log 2 "props_spoof restored (overrides deleted)"
}

# ---------- status：当前值 vs 期望值（供 WebUI 显示） ----------
do_status() {
    echo "{"
    echo "  \"enabled\": \"$(get_config spoof_props_enabled 0)\","
    echo "  \"vbstate\": \"$(getprop ro.boot.verifiedbootstate)\","
    echo "  \"debuggable\": \"$(getprop ro.debuggable)\","
    echo "  \"secure\": \"$(getprop ro.secure)\","
    echo "  \"tags\": \"$(getprop ro.build.tags)\","
    echo "  \"type\": \"$(getprop ro.build.type)\","
    echo "  \"oem_unlock\": \"$(getprop sys.oem_unlock_allowed)\","
    echo "  \"adbd\": \"$(getprop init.svc.adbd)\""
    echo "}"
}

case "$1" in
    apply)   do_apply ;;
    restore) do_restore ;;
    status)  do_status ;;
    *) echo "usage: $0 {apply|restore|status}" ;;
esac
