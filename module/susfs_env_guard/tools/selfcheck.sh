#!/system/bin/sh
# SUSFS环境守护 v6.2 - 自检诊断（POSIX sh / mksh 兼容，禁止 declare -A）
# 用法: selfcheck.sh  （输出文本 + 写 selfcheck_result.json）

. "${0%/*}/lib_common.sh"

PASS=0; WARN=0; FAIL=0
ok(){ PASS=$((PASS+1)); }
wn(){ WARN=$((WARN+1)); echo "[WARN] $*"; }
no(){ FAIL=$((FAIL+1)); echo "[FAIL] $*"; }
ps_(){ PASS=$((PASS+1)); echo "[PASS] $*"; }

echo "===== SUSFS环境守护 v6.2 自检 $(date) ====="

# 1. 文件完整性
echo "--- 文件完整性 ---"
for f in post-fs-data.sh service.sh customize.sh module.prop sepolicy.rule \
         tools/props_spoof.sh tools/randomize.sh tools/pkgmask_setup.sh \
         tools/appops_setup.sh tools/daemon_loop.sh webroot/index.html; do
    if [ -f "$MODDIR/$f" ]; then ok; else no "缺失 $f"; fi
done
[ -f "$CONF" ] && ps_ "配置存在" || wn "配置缺失(用默认)"

# 2. 属性伪装
echo "--- 属性伪装 ---"
G=$(get_config global_spoof_enabled 1)
if [ "$G" = 1 ]; then
    # prop:expected 列表（POSIX 替代关联数组）
    echo "ro.boot.verifiedbootstate:green
ro.boot.vbmeta.device_state:locked
ro.boot.flash.locked:1
ro.debuggable:0
ro.secure:1
ro.build.tags:release-keys
ro.build.type:user" | while IFS=: read -r p e; do
        a=$(getprop "$p")
        [ "$a" = "$e" ] && echo "[PASS] $p=$a" || echo "[FAIL] $p=$a 期望$e"
    done
    # 重新统计（while 子shell不影响外层，这里用文件计数）
    TMPF="$RUN_DIR/.sc_props"; : > "$TMPF"
    echo "ro.boot.verifiedbootstate:green
ro.boot.vbmeta.device_state:locked
ro.boot.flash.locked:1
ro.debuggable:0
ro.secure:1
ro.build.tags:release-keys
ro.build.type:user" | while IFS=: read -r p e; do
        a=$(getprop "$p"); [ "$a" = "$e" ] && echo P >> "$TMPF" || echo F >> "$TMPF"
    done
    P=$(grep -c P "$TMPF"); F=$(grep -c F "$TMPF")
    PASS=$((PASS+P)); FAIL=$((FAIL+F)); rm -f "$TMPF"

    # 多通道一致性：fingerprint 的 incremental 必须 == ro.build.version.incremental
    INC=$(getprop ro.build.version.incremental)
    FP=$(getprop ro.build.fingerprint)
    case "/$INC/" in *"/$FP"*) :;; esac
    echo "$FP" | grep -q "/$INC:" && ps_ "fingerprint 与 incremental 一致($INC)" \
        || no "fingerprint 与 incremental 不一致 INC=$INC"
else
    wn "全局伪装关闭中(显示真值属预期)"
fi

# 3. 硬件只读 ID（内核 hwid_spoof）
echo "--- 硬件只读ID ---"
if [ -f "$HWID_SYSFS/hwid_enabled" ]; then
    HE=$(cat "$HWID_SYSFS/hwid_enabled" 2>/dev/null)
    if [ "$G" = 1 ] && bool_on "$HE"; then
        # 假值是否真正进入驱动
        HS=$(cat "$HWID_SYSFS/hwid_status" 2>/dev/null)
        echo "$HS" | grep -q '^hook=vfs_read(kretprobe)' && ps_ "内核 hwid hook 已注册" || no "hwid hook 未注册"
        echo "$HS" | grep -q '^wlan_mac=..' && ps_ "内核 hwid 已加载假MAC" || no "hwid 假值未就位"
        . "$DATA_DIR/fake_profile.conf" 2>/dev/null
        ACTUAL_WMAC=$(cat /sys/class/net/wlan0/address 2>/dev/null)
        [ "$ACTUAL_WMAC" = "$fake_wmac" ] && ps_ "WLAN MAC 读取已替换" \
            || wn "WLAN MAC 读取未匹配（不修改真实网卡状态，当前=$ACTUAL_WMAC）"
        ACTUAL_SOC=$(cat /sys/devices/soc0/serial_number 2>/dev/null)
        case "$ACTUAL_SOC" in
            "$fake_soc"*) ps_ "SoC Serial 实际读取已替换" ;;
            *) wn "SoC Serial 实际读取未匹配(当前=$ACTUAL_SOC)" ;;
        esac
    else
        wn "hwid_spoof 未使能(enabled=$HE；可接受值为 1/Y)"
    fi
else
    wn "内核无 hwid_spoof（未找到 $HWID_SYSFS）"
fi

# 4. pkgmask
echo "--- pkgmask ---"
if [ -d "$PKG_SYSFS" ]; then
    DU=$(cat "$PKG_SYSFS/deny_uids" 2>/dev/null)
    [ -n "$DU" ] && ps_ "pkgmask deny_uids=$DU" || wn "pkgmask 无 deny_uids(检测方未装?)"
    HP=$(cat "$PKG_SYSFS/hide_proc_enabled" 2>/dev/null)
    [ "$HP" = 1 ] && ps_ "进程隐藏已启用" || wn "进程隐藏未启用"
else
    no "内核无 pkgmask"
fi

# 5. SUSFS
echo "--- SUSFS ---"
SUSFS_DIR="/sys/module/susfs"
if ls -ld "$SUSFS_DIR" >/dev/null 2>&1; then
    ps_ "SUSFS 模块目录存在"
    SUSFS_FILES=$(find "$SUSFS_DIR" -maxdepth 2 -type f 2>/dev/null | head -n 1)
    [ -n "$SUSFS_FILES" ] && ps_ "SUSFS 节点可读取: $SUSFS_FILES" \
        || wn "SUSFS 目录存在但未找到可读取节点"
    if [ -f "$SUSFS_DIR/version" ]; then
        ps_ "SUSFS $(cat "$SUSFS_DIR/version" 2>/dev/null)"
    else
        wn "SUSFS version 节点不存在（可能已启用隐藏版本信息）"
    fi
else
    wn "未检测到 SUSFS（路径隐藏依赖它）"
fi

# 6. 守护进程
echo "--- 守护进程 ---"
DP=$(pidof daemon_loop.sh 2>/dev/null)
[ -n "$DP" ] && ps_ "守护进程运行 PID=$DP" || no "守护进程未运行"

echo "===== 汇总 PASS=$PASS WARN=$WARN FAIL=$FAIL ====="
cat > "$DATA_DIR/selfcheck_result.json" << EOF
{ "timestamp": "$(date +%s)", "pass": $PASS, "warn": $WARN, "fail": $FAIL,
  "global": "$G", "kernel": "$(uname -r)" }
EOF
