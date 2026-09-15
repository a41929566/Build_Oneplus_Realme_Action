#!/system/bin/sh
# SUSFS环境守护 v6.3 - 属性层状态管理
# 设计原则（对抗 Maple 多通道交叉比对 JVM vs getprop vs PropertyUtil）：
#   1) 必须在 post-fs-data（zygote 启动前）执行，使 app fork 时 JVM 固化值即为假值；
#   2) 假指纹一次生成、持久保存，重启不变（频繁变更本身就是异常特征）；
#   3) 只改“个体唯一”段（serial/incremental/fingerprint构建号/MAC），
#      机型/SoC/Android版本/安全补丁等“群体一致”段保持真机，避免跨层不一致；
#   4) 关闭时 resetprop --delete 回落到原始属性区，做到“关闭即漏真”。
#
# 用法: props_spoof.sh {apply|regen|restore|status}

. "${0%/*}/lib_common.sh"

PROFILE="${DATA_DIR}/fake_profile.conf"
ORIG="${BACKUP_DIR}/props_orig.conf"

# 需要覆盖的“锁状态/root 痕迹”属性（期望值）
LOCK_PROPS="ro.debuggable=0
ro.secure=1
ro.adb.secure=1
sys.oem_unlock_allowed=0
ro.build.tags=release-keys
ro.build.type=user
ro.build.selinux=1
init.svc.adbd=stopped"

# fingerprint 各分区位置（值都按同一规则替换 incremental 段）
FP_PROPS="ro.build.fingerprint
ro.vendor.build.fingerprint
ro.product.build.fingerprint
ro.system.build.fingerprint
ro.system_ext.build.fingerprint
ro.odm.build.fingerprint
ro.bootimage.build.fingerprint"

# ---------- 备份原始值（仅一次，绝不覆盖真值；全量备份，含锁状态，便于一键还原与对照） ----------
backup_orig() {
    [ -f "$ORIG" ] && return 0
    {
        # 锁状态原始值也完整留档
        echo "$LOCK_PROPS" | while IFS='=' read -r p v; do
            [ -n "$p" ] && echo "${p}=$(getprop "$p")"
        done
        for p in ro.serialno ro.boot.serialno ro.build.version.incremental ro.build.id \
                 ro.build.display.id net.hostname $FP_PROPS \
                 ro.com.cph.mac_address vendor.cf.address com.cph.bluetooth_mac \
                 ro.com.cph.device_unique_mac persist.vendor.wifi.mac persist.vendor.bt.mac \
                 ro.product.brand ro.product.model ro.product.device ro.product.name \
                 ro.product.manufacturer ro.build.version.release ro.build.version.sdk \
                 ro.vendor.build.security_patch ro.build.version.security_patch; do
            echo "${p}=$(getprop "$p")"
        done
    } > "$ORIG"
}
orig_val() { grep "^$1=" "$ORIG" 2>/dev/null | head -1 | cut -d= -f2-; }

# ---------- 生成/读取持久假 profile ----------
gen_profile() {
    local fake_serial fake_inc fake_wmac fake_bmac
    local fake_soc fake_cid fake_cpu
    fake_serial=$(rand_serial8)
    fake_inc=$(rand_incremental)
    fake_wmac=$(rand_mac)
    fake_bmac=$(rand_mac)
    # 长度必须与真机一致（内核为等长替换，长度不符会跳过该项）：
    #   SoC serial_number / cpuinfo Serial = 16 hex(8B)；UFS CID = 32 hex(16B)
    # rand_hex 的参数是“字节数”，输出为其 2 倍 hex 字符
    fake_soc=$(rand_hex 8)           # 16 hex
    fake_cid=$(rand_hex 16)          # 32 hex
    fake_cpu=$(rand_hex 8)           # 16 hex
    # 兜底：随机源异常时给稳定且长度正确的默认，绝不能留空或长度异常
    [ ${#fake_serial} -lt 8 ] && fake_serial="CN$(rand_hex 3 | tr 'a-f' 'A-F')"
    [ ${#fake_inc} -lt 6 ] && fake_inc="$(date +%Y%m%d)0001"
    [ ${#fake_soc} -lt 16 ] && fake_soc="00$(rand_hex 7)"
    [ ${#fake_cid} -lt 32 ] && fake_cid="00$(rand_hex 15)"
    [ ${#fake_cpu} -lt 16 ] && fake_cpu="00$(rand_hex 7)"
    echo "fake_serial=$fake_serial"     > "$PROFILE"
    echo "fake_inc=$fake_inc"          >> "$PROFILE"
    echo "fake_wmac=$fake_wmac"        >> "$PROFILE"
    echo "fake_bmac=$fake_bmac"        >> "$PROFILE"
    echo "fake_soc=$fake_soc"          >> "$PROFILE"
    echo "fake_cid=$fake_cid"          >> "$PROFILE"
    echo "fake_cpu=$fake_cpu"          >> "$PROFILE"
}
load_profile() {
    [ -f "$PROFILE" ] || gen_profile
    . "$PROFILE"
    # 不完整则补全
    local need=0
    for k in fake_serial fake_inc fake_wmac fake_bmac fake_soc fake_cid fake_cpu; do
        eval "v=\${$k:-}"
        [ -z "$v" ] && need=1
    done
    [ "$need" = 1 ] && gen_profile && . "$PROFILE"
}

# 把一个 fingerprint 里的 incremental 段替换为假值，其余原样
# 标准格式 BRAND/PRODUCT/DEVICE:RELEASE/ID/INCREMENTAL:TYPE/TAGS
# 按 "/" 切分后倒数第2段恒为 "INCREMENTAL:TYPE"，只换其冒号前部分（与厂商/段数无关）
fp_replace_inc() {
    local fp=$1 inc=$2
    echo "$fp" | awk -v inc="$inc" '
    {
        n=split($0,a,"/");
        if (n>=4) {
            split(a[n-1], t, ":");
            t[1]=inc;
            a[n-1]=t[1]":"t[2];
            out=a[1]; for(i=2;i<=n;i++) out=out"/"a[i];
            print out;
        } else print $0;
    }'
}

# ---------- apply ----------
do_apply() {
    init_feature_flags
    backup_orig
    load_profile
    local on; on=$(get_config spoof_props_enabled 0)
    [ "$on" != "1" ] && { do_restore; return; }

    # L0 锁状态
    echo "$LOCK_PROPS" | while IFS='=' read -r p v; do
        [ -n "$p" ] && rp_set "$p" "$v"
    done

    # L1 个体唯一值；每个表面均由独立开关控制。
    if [ "$(get_config spoof_serial 1)" = "1" ]; then
        rp_set ro.serialno "$fake_serial"
        rp_set ro.boot.serialno "$fake_serial"
        rp_set persist.sys.oem.serialno "$fake_serial" 2>/dev/null
    fi
    if [ "$(get_config spoof_build 1)" = "1" ]; then
        rp_set ro.build.version.incremental "$fake_inc"
        for p in $FP_PROPS; do
            real=$(orig_val "$p"); [ -z "$real" ] && real=$(getprop "$p")
            [ -z "$real" ] && continue
            newfp=$(fp_replace_inc "$real" "$fake_inc")
            [ -n "$newfp" ] && rp_set "$p" "$newfp"
        done
        local disp; disp=$(orig_val ro.build.display.id)
        [ -n "$disp" ] && rp_set ro.build.display.id "$(echo "$disp" | sed "s/[0-9]\{6,\}$/$fake_inc/")"
    fi

    # 一加专属 MAC/唯一码属性（与内核 hwid 假 MAC 对齐，避免属性与 sysfs 不一致）
    if [ "$(get_config spoof_wifi_mac 0)" = "1" ] &&
       { [ "$(get_config identity_consistency_guard 1)" != "1" ] ||
         [ "$(get_config spoof_hwid_enabled 0)" = "1" ]; }; then
        rp_set ro.com.cph.mac_address "$fake_wmac" 2>/dev/null
        rp_set vendor.cf.address "$fake_wmac" 2>/dev/null
        rp_set ro.com.cph.device_unique_mac "$fake_wmac" 2>/dev/null
        rp_set persist.vendor.wifi.mac "$fake_wmac" 2>/dev/null
    elif [ "$(get_config spoof_wifi_mac 0)" = "1" ]; then
        log 1 "wifi MAC properties skipped: kernel HWID interception is not enabled"
    fi
    if [ "$(get_config spoof_bt_mac 0)" = "1" ] &&
       { [ "$(get_config identity_consistency_guard 1)" != "1" ] ||
         [ "$(get_config spoof_hwid_enabled 0)" = "1" ]; }; then
        rp_set com.cph.bluetooth_mac "$fake_bmac" 2>/dev/null
        rp_set persist.vendor.bt.mac "$fake_bmac" 2>/dev/null
    elif [ "$(get_config spoof_bt_mac 0)" = "1" ]; then
        log 1 "bluetooth MAC properties skipped: kernel HWID interception is not enabled"
    fi
    # 主机名（默认常含机型，统一中性）
    rp_set net.hostname "localhost" 2>/dev/null

    log 2 "props_spoof applied serial=$fake_serial inc=$fake_inc"
}

# ---------- regen：一键随机（重新生成假值并应用） ----------
do_regen() {
    rm -f "$PROFILE"
    # android_id 也重新随机（由 randomize.sh 负责，这里只重生成属性 profile）
    gen_profile
    do_apply
}

# ---------- restore：删除全部覆盖，回落真值 ----------
do_restore() {
    for pair in $LOCK_PROPS; do rp_del "${pair%%=*}"; done
    for p in ro.serialno ro.boot.serialno persist.sys.oem.serialno \
             ro.build.version.incremental $FP_PROPS ro.build.display.id \
             ro.com.cph.mac_address vendor.cf.address com.cph.bluetooth_mac \
             ro.com.cph.device_unique_mac persist.vendor.wifi.mac persist.vendor.bt.mac \
             net.hostname; do
        rp_del "$p"
    done
    log 2 "props_spoof restored (overrides deleted)"
}

# ---------- status：当前值 vs 真值 vs 假值（供 WebUI 实时反馈） ----------
do_status() {
    load_profile 2>/dev/null
    echo "{"
    echo "  \"enabled\": \"$(get_config spoof_props_enabled 0)\","
    echo "  \"fake_serial\": \"$fake_serial\","
    echo "  \"cur_serial\": \"$(getprop ro.serialno)\","
    echo "  \"orig_serial\": \"$(orig_val ro.serialno)\","
    echo "  \"fake_inc\": \"$fake_inc\","
    echo "  \"cur_inc\": \"$(getprop ro.build.version.incremental)\","
    echo "  \"cur_fp\": \"$(getprop ro.build.fingerprint)\","
    echo "  \"orig_fp\": \"$(orig_val ro.build.fingerprint)\","
    echo "  \"vbstate\": \"$(getprop ro.boot.verifiedbootstate)\","
    echo "  \"debuggable\": \"$(getprop ro.debuggable)\","
    echo "  \"tags\": \"$(getprop ro.build.tags)\","
    echo "  \"type\": \"$(getprop ro.build.type)\","
    echo "  \"oem_unlock\": \"$(getprop sys.oem_unlock_allowed)\","
    echo "  \"model\": \"$(getprop ro.product.model)\","
    echo "  \"device\": \"$(getprop ro.product.device)\","
    echo "  \"brand\": \"$(getprop ro.product.brand)\""
    echo "}"
}

case "$1" in
    apply)   do_apply ;;
    regen)   do_regen ;;
    restore) do_restore ;;
    status)  do_status ;;
    *) echo "usage: $0 {apply|regen|restore|status}" ;;
esac
