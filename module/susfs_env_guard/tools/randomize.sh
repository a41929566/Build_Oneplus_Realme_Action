#!/system/bin/sh
# SUSFS环境守护 v6.2 - 硬件ID状态管理
# 分两层：
#   A) 用户态可改：Settings.Secure android_id
#   B) 只读硬件ID（SoC serial / cpuinfo / UFS CID / 网卡MAC）：只能靠内核 hwid_spoof
#      驱动在 read(2) 返回路径上等长替换。本脚本把“假值”写入 pkgmask sysfs。
# 假值与 props_spoof 共用同一 fake_profile.conf，保证 属性层 == sysfs层（多通道一致）。
#
# 用法: randomize.sh {apply|regen|restore|status}

. "${0%/*}/lib_common.sh"

HW_DIR="$HWID_SYSFS"
AID_BACKUP="$BACKUP_DIR/android_id.txt"

hwid_supported() { [ -f "$HW_DIR/hwid_enabled" ] && [ -f "$HW_DIR/hwid_reload" ]; }

# 保证 profile 全套键齐全（杜绝空值写入内核：空 SoC/CID/MAC = 明显异常）
# 无论本脚本与 props_spoof 的调用先后，都能自洽补全。
ensure_profile() {
    [ -f "$PROFILE" ] || : > "$PROFILE"
    _need() { grep -q "^$1=" "$PROFILE" 2>/dev/null; }
    _need fake_serial || echo "fake_serial=$(rand_serial8)" >> "$PROFILE"
    _need fake_inc    || echo "fake_inc=$(rand_incremental)" >> "$PROFILE"
    _need fake_wmac   || echo "fake_wmac=$(rand_mac)" >> "$PROFILE"
    _need fake_bmac   || echo "fake_bmac=$(rand_mac)" >> "$PROFILE"
    _need fake_soc    || echo "fake_soc=$(rand_hex 8)" >> "$PROFILE"
    _need fake_cid    || echo "fake_cid=$(rand_hex 16)" >> "$PROFILE"
    _need fake_cpu    || echo "fake_cpu=$(rand_hex 8)" >> "$PROFILE"
    _need fake_aid    || echo "fake_aid=$(rand_hex 8)" >> "$PROFILE"
}

# 把假值批量写入内核并 reload
apply_kernel_hwid() {
    hwid_supported || return 1
    . "$PROFILE"
    local uids
    uids=$(get_config hwid_uids "")
    # 作用域：默认全局（空）。可在 conf 配 hwid_uids=10123,10124 仅对特定 app
    echo "$uids" > "$HW_DIR/hwid_uids" 2>/dev/null
    echo "$fake_soc"  > "$HW_DIR/hwid_soc_serial" 2>/dev/null
    echo "$fake_cid"  > "$HW_DIR/hwid_cid" 2>/dev/null
    echo "$fake_wmac" > "$HW_DIR/hwid_wlan_mac" 2>/dev/null
    echo "$fake_bmac" > "$HW_DIR/hwid_bt_mac" 2>/dev/null
    echo "$fake_cpu"  > "$HW_DIR/hwid_cpu_serial" 2>/dev/null
    echo 1 > "$HW_DIR/hwid_reload" 2>/dev/null
    echo 1 > "$HW_DIR/hwid_enabled" 2>/dev/null
    bool_on "$(cat "$HW_DIR/hwid_enabled" 2>/dev/null)"
}

do_apply() {
    ensure_profile; . "$PROFILE"
    local on; on=$(get_config global_spoof_enabled 1)

    # A) android_id（先备份真值一次）
    if [ ! -f "$AID_BACKUP" ]; then
        settings get secure android_id 2>/dev/null > "$AID_BACKUP"
    fi
    if [ "$on" = "1" ] && [ "$(get_config spoof_android_id 1)" = "1" ]; then
        settings put secure android_id "$fake_aid" 2>/dev/null
    fi

    # B) 内核只读 ID（优先内核 hwid_spoof；不支持时回退到用户态 bind mount）
    if [ "$on" = "1" ]; then
        if apply_kernel_hwid; then
            log 2 "kernel hwid applied soc=$fake_soc wmac=$fake_wmac"
            echo "KERNEL_HWID=OK"
            touch "$DATA_DIR/hwid_method_kernel"
            rm -f "$DATA_DIR/hwid_method_userspace"
        elif [ "$(get_config hwid_userspace_fallback 0)" = "1" ]; then
            log 0 "内核无 hwid_spoof；拒绝使用会改动网卡状态的用户态回退"
            echo "KERNEL_HWID=DISABLED_UNSAFE_FALLBACK"
        else
            log 1 "内核无 hwid_spoof 且 userspace fallback 已禁用，硬件ID未伪装"
            echo "KERNEL_HWID=DISABLED"
        fi
    else
        do_restore
    fi
}

do_regen() {
    # 重新随机硬件层（android_id + 内核值），属性 profile 由 props_spoof regen 统一重建
    sed -i '/^fake_aid=/d' "$PROFILE" 2>/dev/null
    ensure_profile
    do_apply
}

do_restore() {
    # 关闭内核拦截 -> app 重新读到真值（该漏就漏）
    if hwid_supported; then
        echo 0 > "$HW_DIR/hwid_enabled" 2>/dev/null
    fi
    # 卸载用户态 bind mount（如有）
    sh "$MODDIR/tools/hwid_userspace.sh" umount 2>/dev/null
    rm -f "$DATA_DIR/hwid_method_kernel" "$DATA_DIR/hwid_method_userspace"
    # android_id 还原
    if [ -f "$AID_BACKUP" ]; then
        local orig; orig=$(cat "$AID_BACKUP")
        [ -n "$orig" ] && settings put secure android_id "$orig" 2>/dev/null
    fi
    log 2 "hardware id restore: hwid disabled, android_id restored"
}

# 真实 sysfs 读取（app 视角；内核开启后这里 root 仍可能读到真值，故同时给 hwid_status）
read_real() {
    case "$1" in
        soc) for f in /sys/devices/soc0/serial_number /sys/devices/soc/serial_number; do
                 [ -r "$f" ] && { cat "$f" 2>/dev/null; return; }
             done; echo "N/A" ;;
        cid) cat /sys/block/sda/device/cid 2>/dev/null || cat /sys/block/mmcblk0/device/cid 2>/dev/null || echo "N/A" ;;
        wmac) cat /sys/class/net/wlan0/address 2>/dev/null || echo "N/A" ;;
        cpu) grep -m1 -i '^Serial' /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "N/A" ;;
    esac
}

do_status() {
    ensure_profile 2>/dev/null; . "$PROFILE" 2>/dev/null
    local sup="0"; hwid_supported && sup="1"
    local en="0"; [ "$sup" = 1 ] && en=$(cat "$HW_DIR/hwid_enabled" 2>/dev/null)
    # 判断当前生效方式
    local method="none"
    [ -f "$DATA_DIR/hwid_method_kernel" ]     && method="kernel_driver"
    [ -f "$DATA_DIR/hwid_method_userspace" ]  && method="userspace_fallback"
    # 回读驱动内部固定值
    local ks=""; [ "$sup" = 1 ] && ks=$(cat "$HW_DIR/hwid_status" 2>/dev/null)
    local drv_soc drv_wmac drv_bmac drv_cid drv_cpu
    drv_soc=$(echo "$ks" | grep '^soc_serial=' | cut -d= -f2-)
    drv_cid=$(echo "$ks" | grep '^cid=' | cut -d= -f2-)
    drv_wmac=$(echo "$ks" | grep '^wlan_mac=' | cut -d= -f2-)
    drv_bmac=$(echo "$ks" | grep '^bt_mac=' | cut -d= -f2-)
    drv_cpu=$(echo "$ks" | grep '^cpu_serial=' | cut -d= -f2-)
    echo "{"
    echo "  \"method\": \"$method\","
    echo "  \"kernel_supported\": \"$sup\","
    echo "  \"enabled\": \"$en\","
    echo "  \"fake_aid\": \"$fake_aid\","
    echo "  \"cur_aid\": \"$(settings get secure android_id 2>/dev/null)\","
    echo "  \"fake_soc\": \"$fake_soc\","
    echo "  \"drv_soc\": \"$drv_soc\","
    echo "  \"fake_cid\": \"$fake_cid\","
    echo "  \"drv_cid\": \"$drv_cid\","
    echo "  \"fake_cpu\": \"$fake_cpu\","
    echo "  \"drv_cpu\": \"$drv_cpu\","
    echo "  \"fake_wmac\": \"$fake_wmac\","
    echo "  \"drv_wmac\": \"$drv_wmac\","
    echo "  \"fake_bmac\": \"$fake_bmac\","
    echo "  \"drv_bmac\": \"$drv_bmac\","
    echo "  \"real_wmac_node\": \"$(read_real wmac)\","
    echo "  \"real_soc_node\": \"$(read_real soc)\""
    echo "}"
}

case "$1" in
    apply) do_apply ;;
    regen) do_regen ;;
    restore) do_restore ;;
    status) do_status ;;
    *) echo "usage: $0 {apply|regen|restore|status}" ;;
esac