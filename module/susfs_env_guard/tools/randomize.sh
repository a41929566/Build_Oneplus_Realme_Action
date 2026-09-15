#!/system/bin/sh
# SUSFS环境守护 v6.3 - 硬件ID状态管理
# 分两层：
#   A) 用户态可改：Settings.Secure android_id
#   B) 只读硬件ID（SoC serial / cpuinfo / UFS CID / 网卡MAC）：只能靠内核 hwid_spoof
#      驱动在 read(2) 返回路径上等长替换。本脚本把“假值”写入 pkgmask sysfs。
# 假值与 props_spoof 共用同一 fake_profile.conf，保证 属性层 == sysfs层（多通道一致）。
#
# 用法: randomize.sh {apply|regen|restore|status}

. "${0%/*}/lib_common.sh"

HW_DIR="$HWID_SYSFS"
AID_USER=0
AID_BACKUP="$BACKUP_DIR/android_id.user${AID_USER}.txt"
STATE_FILE="$DATA_DIR/identity_state"

hwid_supported() {
    [ -f "$HW_DIR/hwid_enabled" ] &&
    [ -f "$HW_DIR/hwid_reload" ] &&
    [ -r "$HW_DIR/hwid_status" ]
}
write_node() {
    local node=$1 value=$2
    [ -w "$HW_DIR/$node" ] || return 1
    printf '%s' "$value" > "$HW_DIR/$node" 2>/dev/null
}
aid_read() {
    settings --user "$AID_USER" get secure android_id 2>/dev/null |
        tr -d '\r\n'
}
aid_valid() {
    case "$1" in
        ''|null|NULL|unknown|Unknown) return 1 ;;
        *) return 0 ;;
    esac
}
backup_android_id() {
    local current
    [ -s "$AID_BACKUP" ] && return 0
    current=$(aid_read)
    aid_valid "$current" || return 1
    printf '%s\n' "$current" > "$AID_BACKUP"
}
apply_android_id() {
    local i current
    backup_android_id || {
        log 1 "android_id backup deferred: settings service is not ready"
        return 2
    }
    i=0
    while [ "$i" -lt 5 ]; do
        settings --user "$AID_USER" put secure android_id "$fake_aid" 2>/dev/null
        current=$(aid_read)
        [ "$current" = "$fake_aid" ] && return 0
        i=$((i+1))
        sleep 1
    done
    log 0 "android_id verification failed: expected=$fake_aid actual=$current"
    return 1
}

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
        write_node hwid_uids "$uids"          || log 0 "WARN: hwid_uids write failed"
    write_node hwid_soc_serial "$fake_soc"  || log 0 "WARN: hwid_soc_serial write failed"
    write_node hwid_cid "$fake_cid"         || log 0 "WARN: hwid_cid write failed"
    write_node hwid_wlan_mac "$fake_wmac"   || log 0 "WARN: hwid_wlan_mac write failed"
    write_node hwid_bt_mac "$fake_bmac"     || log 0 "WARN: hwid_bt_mac write failed"
    write_node hwid_cpu_serial "$fake_cpu"  || log 0 "WARN: hwid_cpu_serial write failed"

    # 核心操作必须执行
    write_node hwid_reload 1 || return 1
    write_node hwid_enabled 1 || return 1
    bool_on "$(cat "$HW_DIR/hwid_enabled" 2>/dev/null)" || return 1
    local status
    status=$(cat "$HW_DIR/hwid_status" 2>/dev/null)
    printf '%s\n' "$status" | grep -q 'hook_active=1' || {
        log 0 "hwid hook is not active after configuration"
        return 1
    }
    printf '%s\n' "$status" | grep -q "^soc_serial=$fake_soc$" || return 1
    printf '%s\n' "$status" | grep -q "^cid=$fake_cid$" || return 1
    printf '%s\n' "$status" | grep -q "^wlan_mac=$fake_wmac$" || return 1
    printf '%s\n' "$status" | grep -q "^bt_mac=$fake_bmac$" || return 1
    printf '%s\n' "$status" | grep -q "^cpu_serial=$fake_cpu$" || return 1
    return 0
}

do_apply() {
    init_feature_flags
    ensure_profile; . "$PROFILE"
    local hw_on; hw_on=$(get_config spoof_hwid_enabled 0)
    local aid_on; aid_on=$(get_config spoof_android_id 0)

    printf '%s\n' applying > "$STATE_FILE"
    # A) Android ID is only touched when Settings has a valid value.
    local aid_rc=0
    if [ "$aid_on" = "1" ]; then
        apply_android_id || aid_rc=$?
        [ "$aid_rc" = 1 ] && {
            printf '%s\n' rolled-back > "$STATE_FILE"
            do_restore
            printf '%s\n' rolled-back > "$STATE_FILE"
            return 1
        }
    fi

    # B) 内核只读 ID（优先内核 hwid_spoof；不支持时回退到用户态 bind mount）
    if [ "$hw_on" = "1" ]; then
        if apply_kernel_hwid; then
            log 2 "kernel hwid applied soc=$fake_soc wmac=$fake_wmac"
            echo "KERNEL_HWID=OK"
            touch "$DATA_DIR/hwid_method_kernel"
            rm -f "$DATA_DIR/hwid_method_userspace"
        elif [ "$(get_config hwid_userspace_fallback 0)" = "1" ]; then
            log 0 "内核无 hwid_spoof；拒绝使用会改动网卡状态的用户态回退"
            echo "KERNEL_HWID=DISABLED_UNSAFE_FALLBACK"
            do_restore
            printf '%s\n' rolled-back > "$STATE_FILE"
            return 1
        else
            log 1 "内核无 hwid_spoof 且 userspace fallback 已禁用，硬件ID未伪装"
            echo "KERNEL_HWID=DISABLED"
            do_restore
            printf '%s\n' rolled-back > "$STATE_FILE"
            return 1
        fi
    else
        restore_kernel_hwid
    fi
    if [ "$aid_rc" = 2 ]; then
        printf '%s\n' pending > "$STATE_FILE"
    elif [ "$aid_on" != "1" ] && [ "$hw_on" != "1" ]; then
        printf '%s\n' restored > "$STATE_FILE"
    else
        printf '%s\n' applied > "$STATE_FILE"
    fi
}

do_regen() {
    # 重新随机硬件层（android_id + 内核值），属性 profile 由 props_spoof regen 统一重建
    sed -i '/^fake_aid=/d' "$PROFILE" 2>/dev/null
    ensure_profile
    do_apply
}

restore_kernel_hwid() {
    if hwid_supported; then
        echo 0 > "$HW_DIR/hwid_enabled" 2>/dev/null
    fi
    rm -f "$DATA_DIR/hwid_method_kernel" "$DATA_DIR/hwid_method_userspace"
}
restore_android_id() {
    sh "$MODDIR/tools/hwid_userspace.sh" umount 2>/dev/null
    if [ -f "$AID_BACKUP" ]; then
        local orig; orig=$(cat "$AID_BACKUP")
        aid_valid "$orig" && settings --user "$AID_USER" put secure android_id "$orig" 2>/dev/null
    fi
}
do_restore() {
    restore_kernel_hwid
    restore_android_id
    printf '%s\n' restored > "$STATE_FILE"
    log 2 "hardware id restore: hwid disabled, android_id restored"
}
restore_aid_only() {
    restore_android_id
    printf '%s\n' restored > "$STATE_FILE"
    log 2 "android id restored"
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
    echo "  \"cur_aid\": \"$(aid_read)\","
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
    restore_aid) restore_aid_only ;;
    status) do_status ;;
    *) echo "usage: $0 {apply|regen|restore|status}" ;;
esac
