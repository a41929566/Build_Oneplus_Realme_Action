#!/system/bin/sh
# SUSFS Env Guard v3.0 - randomize.sh
# 内部自洽规则：
#   ① fake_cpu == fake_soc  （真机 cpuinfo Serial 和 SoC serial_number 是同一芯片ID）
#   ② fake_bmac 复用 fake_wmac 的 OUI  （真机 WiFi 和蓝牙同厂商）
# 用法: randomize.sh {apply|regen|restore|status}

. "${0%/*}/lib_common.sh"

HW_DIR="$HWID_SYSFS"
AID_USER=0
AID_BACKUP="$BACKUP_DIR/android_id.user${AID_USER}.txt"
STATE_FILE="$DATA_DIR/identity_state"

hwid_supported() {
    [ -f "$HW_DIR/hwid_enabled" ] && [ -f "$HW_DIR/hwid_reload" ] && [ -r "$HW_DIR/hwid_status" ]
}

write_node() {
    [ -w "$HW_DIR/$1" ] || return 1
    printf '%s' "$2" > "$HW_DIR/$1" 2>/dev/null
}

aid_read() {
    settings --user "$AID_USER" get secure android_id 2>/dev/null | tr -d '\r\n'
}

aid_valid() {
    case "$1" in
        ''|null|NULL|unknown|Unknown) return 1 ;;
        *) return 0 ;;
    esac
}

backup_android_id() {
    [ -s "$AID_BACKUP" ] && return 0
    local c
    c=$(aid_read)
    aid_valid "$c" || return 1
    printf '%s\n' "$c" > "$AID_BACKUP"
}

apply_android_id() {
    backup_android_id || { log 1 "android_id backup deferred"; return 2; }
    local i=0 c
    while [ "$i" -lt 5 ]; do
        settings --user "$AID_USER" put secure android_id "$fake_aid" 2>/dev/null
        c=$(aid_read)
        [ "$c" = "$fake_aid" ] && return 0
        i=$((i+1))
        sleep 1
    done
    return 1
}

# BT MAC = WLAN MAC 前 3 段 + 随机后 3 段
gen_bt_mac() {
    local oui hx t1 t2 t3
    oui=$(echo "$1" | cut -d: -f1-3)
    # 兜底：OUI 格式异常时用本地管理默认前缀
    case "$oui" in
        ??:??:??) ;;
        *) oui="02:00:00" ;;
    esac
    hx=$(rand_hex 3)
    # 兜底：确保 hx 是 6 字符（防极端情况 rand_hex 少字符）
    while [ ${#hx} -lt 6 ]; do hx="${hx}0"; done
    hx=$(echo "$hx" | cut -c1-6)
    t1=$(echo "$hx" | cut -c1-2)
    t2=$(echo "$hx" | cut -c3-4)
    t3=$(echo "$hx" | cut -c5-6)
    echo "$oui:$t1:$t2:$t3"
}

# 全新生成 profile（内部自洽）
gen_profile_fresh() {
    local fs fi fw fsoc fcid faid
    fs=$(rand_serial8)
    fi=$(rand_incremental)
    fw=$(rand_mac)
    fsoc=$(rand_hex 8)
    fcid=$(rand_hex 16)
    faid=$(rand_hex 8)
    {
        echo "fake_serial=$fs"
        echo "fake_inc=$fi"
        echo "fake_wmac=$fw"
        echo "fake_bmac=$(gen_bt_mac "$fw")"
        echo "fake_soc=$fsoc"
        echo "fake_cid=$fcid"
        echo "fake_cpu=$fsoc"
        echo "fake_aid=$faid"
    } > "$PROFILE"
}

# 补全 profile（幂等）
ensure_profile() {
    [ -f "$PROFILE" ] || : > "$PROFILE"
    grep -q '^fake_serial=' "$PROFILE" || echo "fake_serial=$(rand_serial8)" >> "$PROFILE"
    grep -q '^fake_inc=' "$PROFILE" || echo "fake_inc=$(rand_incremental)" >> "$PROFILE"
    grep -q '^fake_wmac=' "$PROFILE" || echo "fake_wmac=$(rand_mac)" >> "$PROFILE"
    if ! grep -q '^fake_bmac=' "$PROFILE"; then
        local w
        w=$(grep '^fake_wmac=' "$PROFILE" | head -1 | cut -d= -f2)
        echo "fake_bmac=$(gen_bt_mac "$w")" >> "$PROFILE"
    fi
    grep -q '^fake_soc=' "$PROFILE" || echo "fake_soc=$(rand_hex 8)" >> "$PROFILE"
    grep -q '^fake_cid=' "$PROFILE" || echo "fake_cid=$(rand_hex 16)" >> "$PROFILE"
    if ! grep -q '^fake_cpu=' "$PROFILE"; then
        local s
        s=$(grep '^fake_soc=' "$PROFILE" | head -1 | cut -d= -f2)
        echo "fake_cpu=$s" >> "$PROFILE"
    fi
    grep -q '^fake_aid=' "$PROFILE" || echo "fake_aid=$(rand_hex 8)" >> "$PROFILE"
}

apply_kernel_hwid() {
    hwid_supported || return 1
    . "$PROFILE"
    write_node hwid_uids "$(get_config hwid_uids "")"
    write_node hwid_soc_serial "$fake_soc"
    write_node hwid_cid "$fake_cid"
    write_node hwid_wlan_mac "$fake_wmac"
    write_node hwid_bt_mac "$fake_bmac"
    write_node hwid_cpu_serial "$fake_cpu"
    write_node hwid_reload 1 || return 1
    write_node hwid_enabled 1 || return 1
    return 0
}

do_apply() {
    init_feature_flags
    ensure_profile
    . "$PROFILE"
    local hw_on aid_on
    hw_on=$(get_config spoof_hwid_enabled 0)
    aid_on=$(get_config spoof_android_id 0)
    echo applying > "$STATE_FILE"
    [ "$aid_on" = "1" ] && apply_android_id
    if [ "$hw_on" = "1" ]; then
        if apply_kernel_hwid; then
            echo "KERNEL_HWID=OK"
            touch "$DATA_DIR/hwid_method_kernel"
        else
            echo "KERNEL_HWID=FAILED"
            return 1
        fi
    fi
    echo applied > "$STATE_FILE"
}

do_regen() {
    gen_profile_fresh
    do_apply
}

do_restore() {
    hwid_supported && echo 0 > "$HW_DIR/hwid_enabled" 2>/dev/null
    rm -f "$DATA_DIR/hwid_method_kernel"
    echo restored > "$STATE_FILE"
}

do_status() {
    ensure_profile
    . "$PROFILE"
    echo "soc=$fake_soc"
    echo "cid=$fake_cid"
    echo "cpu=$fake_cpu"
    echo "wmac=$fake_wmac"
    echo "bmac=$fake_bmac"
}

case "$1" in
    apply) do_apply ;;
    regen) do_regen ;;
    restore) do_restore ;;
    status) do_status ;;
    *) echo "usage: $0 {apply|regen|restore|status}" ;;
esac
