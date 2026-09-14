#!/system/bin/sh
# SUSFS环境守护 v6.2 - 硬件ID用户态回退层
# 当内核没有 hwid_spoof 驱动时，可选择使用 bind mount 回退层
# 在用户态实现 SoC serial / UFS CID / MAC 的全局伪装。
#
# 用法: hwid_userspace.sh {mount|umount|restore|status}
#
# mount   - 生成假值文件并 bind mount 覆盖真实 sysfs 节点（全局生效）
# umount  - 卸载 bind mount，恢复原始节点可读
# restore - 同 umount + 还原 WiFi MAC
# status  - 输出当前挂载状态 JSON

. "${0%/*}/lib_common.sh"

FAKE_DIR="$DATA_DIR/hwid_fake"
mkdir -p "$FAKE_DIR"

# ---------- 假值文件生成（幂等） ----------
generate_fakes() {
    [ -f "$PROFILE" ] || : > "$PROFILE"
    # 补全 profile（与 randomize.sh ensure_profile 同步逻辑）
    _need() { grep -q "^$1=" "$PROFILE" 2>/dev/null; }
    _need fake_soc  || echo "fake_soc=$(rand_hex 8)" >> "$PROFILE"
    _need fake_cid  || echo "fake_cid=$(rand_hex 16)" >> "$PROFILE"
    _need fake_wmac || echo "fake_wmac=$(rand_mac)" >> "$PROFILE"
    _need fake_bmac || echo "fake_bmac=$(rand_mac)" >> "$PROFILE"
    . "$PROFILE"

    # 生成假值纯文本文件（bind mount 源）
    echo "$fake_soc"  > "$FAKE_DIR/soc_serial"
    echo "$fake_cid"  > "$FAKE_DIR/cid"
    echo "$fake_wmac" > "$FAKE_DIR/wlan_mac"
    echo "$fake_bmac" > "$FAKE_DIR/bt_mac"

    # cpuinfo：保留真实 CPU 信息，只替换 Serial 行
    cat /proc/cpuinfo 2>/dev/null | sed "s/^Serial[[:space:]]*:.*/Serial\t\t: $fake_cpu/" > "$FAKE_DIR/cpuinfo"

    log 2 "hwid_userspace: fakes generated soc=[$fake_soc] cid=[$fake_cid] wmac=[$fake_wmac]"
}

# ---------- 检测真实设备节点 ----------
detect_soc_node() {
    for f in /sys/devices/soc0/serial_number /sys/devices/soc/serial_number; do
        [ -f "$f" ] && { echo "$f"; return; }
    done
}
detect_cid_node() {
    for f in /sys/block/sda/device/cid /sys/block/mmcblk0/device/cid; do
        [ -f "$f" ] && { echo "$f"; return; }
    done
}
detect_wlan_iface() {
    for iface in wlan0 eth0; do
        [ -d "/sys/class/net/$iface" ] && { echo "$iface"; return; }
    done
}

# ---------- bind mount ----------
do_mount() {
    generate_fakes

    local mounted=0

    # SoC serial
    local soc_node; soc_node=$(detect_soc_node)
    if [ -n "$soc_node" ] && [ -f "$FAKE_DIR/soc_serial" ]; then
        mount --bind "$FAKE_DIR/soc_serial" "$soc_node" 2>/dev/null && mounted=$((mounted+1))
        log 2 "hwid_userspace: bind mount $soc_node"
    fi

    # UFS CID
    local cid_node; cid_node=$(detect_cid_node)
    if [ -n "$cid_node" ] && [ -f "$FAKE_DIR/cid" ]; then
        mount --bind "$FAKE_DIR/cid" "$cid_node" 2>/dev/null && mounted=$((mounted+1))
        log 2 "hwid_userspace: bind mount $cid_node"
    fi

    # /proc/cpuinfo（可选，有副作用的最后手段）
    if [ "$(get_config hwid_userspace_cpuinfo 0)" = "1" ] && [ -f "$FAKE_DIR/cpuinfo" ]; then
        mount --bind "$FAKE_DIR/cpuinfo" /proc/cpuinfo 2>/dev/null && mounted=$((mounted+1))
        log 2 "hwid_userspace: bind mount /proc/cpuinfo (config enabled)"
    fi

        # Never change a live net_device MAC here; doing so can break Wi-Fi, BT
        # pairing, DHCP leases, or firmware state. Kernel read interception is
        # the only supported MAC path.

    # 标记回退已激活
    touch "$FAKE_DIR/.mounted"
    return $mounted
}

# ---------- 卸载 ----------
do_umount() {
    local soc_node; soc_node=$(detect_soc_node)
    [ -n "$soc_node" ] && umount "$soc_node" 2>/dev/null

    local cid_node; cid_node=$(detect_cid_node)
    [ -n "$cid_node" ] && umount "$cid_node" 2>/dev/null

    umount /proc/cpuinfo 2>/dev/null

    rm -f "$FAKE_DIR/.mounted"
    log 2 "hwid_userspace: all bind mounts released"
}

do_restore() {
    do_umount
    # WiFi MAC 还原：没有真值可回退，仅关闭即可
    log 2 "hwid_userspace: restored (WiFi MAC 重启后自动恢复真值)"
}

# ---------- 状态 ----------
do_status() {
    . "$PROFILE" 2>/dev/null
    local soc_node; soc_node=$(detect_soc_node)
    local cid_node; cid_node=$(detect_cid_node)
    local wlan_iface; wlan_iface=$(detect_wlan_iface)
    local active=0; [ -f "$FAKE_DIR/.mounted" ] && active=1

    echo "{"
    echo "  \"method\": \"userspace_fallback\","
    echo "  \"active\": \"$active\","
    echo "  \"fake_soc\": \"$fake_soc\","
    echo "  \"fake_cid\": \"$fake_cid\","
    echo "  \"fake_wmac\": \"$fake_wmac\","
    echo "  \"fake_bmac\": \"$fake_bmac\","
    echo "  \"soc_node\": \"$soc_node\","
    echo "  \"cid_node\": \"$cid_node\","
    echo "  \"wlan_iface\": \"$wlan_iface\","
    echo "  \"cur_wmac\": \"$(cat /sys/class/net/$wlan_iface/address 2>/dev/null)\","
    echo "  \"cur_soc\": \"$(cat "$soc_node" 2>/dev/null)\","
    echo "  \"cur_cid\": \"$(cat "$cid_node" 2>/dev/null)\""
    echo "}"
}

case "$1" in
    mount)   do_mount ;;
    umount)  do_umount ;;
    restore) do_restore ;;
    status)  do_status ;;
    *)       echo "usage: $0 {mount|umount|restore|status}" ;;
esac