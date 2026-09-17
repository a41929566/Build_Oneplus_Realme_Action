#!/system/bin/sh
# SUSFS Env Guard v3.0 - susfs_fix.sh
# 独立 SUSFS 修复脚本，由 run.sh 和 daemon_loop.sh 共同调用
#
# 【v3.1 关键修复】
#   - hide_common_paths：POSIX shell 管道陷阱
#     旧版：collect_paths | while read p; do "$ks" ... done
#     管道右侧是子 shell，$ks 局部变量丢失，命令变成 "" 静默失败
#     新版：collect_paths > tmplist; while ... < tmplist
#   - 变量名统一：SUSFS_PATH_HIDE → SPOOF_PATH_HIDE
#   - 变量名统一：SUSFS_PATH_HIDE_EXTRA → PATH_HIDE_EXTRA

. "${0%/*}/lib_common.sh"

KS=""
for p in /data/adb/ksu/bin/ksu_susfs /data/adb/ksud/bin/ksu_susfs /data/adb/modules/susfs4ksu/bin/ksu_susfs; do
    [ -x "$p" ] && KS="$p" && break
done
[ -z "$KS" ] && { echo "SUSFS_FIX=NO_TOOL"; exit 1; }

D="$MODDIR/config"
F="$D/cmdline_fake.txt"
B="$D/bootconfig_spoof.txt"
USER_PATHS_FILE="$DATA_DIR/user_hidden_paths.txt"

# ---------- 1) cmdline 伪装 ----------
cat /proc/cmdline | tr '\n' ' ' | sed '
    s/oplusboot\.verifiedbootstate=[a-z]*/oplusboot.verifiedbootstate=green/g
    s/androidboot\.verifiedbootstate=[a-z]*/androidboot.verifiedbootstate=green/g
    s/androidboot\.vbmeta\.device_state=[a-z]*/androidboot.vbmeta.device_state=locked/g
    s/androidboot\.selinux=[a-z]*/androidboot.selinux=enforcing/g
    s/oplusboot\.mode=[a-z]*/oplusboot.mode=normal/g
' > "$F"
echo >> "$F"
cp "$F" "$D/cmdline_spoof.txt"

# ---------- 2) bootconfig 伪装 ----------
[ -s "$B" ] || { echo "SUSFS_FIX=NO_BOOTCONFIG_TEMPLATE"; exit 1; }

# ---------- 3) 注册 cmdline/bootconfig 重定向 ----------
"$KS" config cmdline_or_bootconfig remove 2>/dev/null
"$KS" config cmdline_or_bootconfig add "$B" 2>/dev/null
"$KS" set_cmdline_or_bootconfig "$B" 2>/dev/null

"$KS" config open_redirect remove /proc/cmdline 2>/dev/null
"$KS" config open_redirect add /proc/cmdline "$F" 3 2>/dev/null
"$KS" add_open_redirect /proc/cmdline "$F" 3 2>/dev/null

# ---------- 4) SUSFS 路径循环隐藏 ----------
# 收集三类路径：内置通用 + 配置文件额外 + 用户手动追加
# 【关键】只输出到 stdout，由调用者重定向到文件
collect_paths() {
    local p

    # 内置通用路径（存在才输出）
    for p in \
        /data/adb \
        /data/adb/ksu \
        /data/adb/ksu/bin \
        /data/adb/ksud \
        /data/adb/modules \
        /data/adb/zygisk \
        /data/adb/modules/rezygisk \
        /data/adb/modules/zygisk-assistant \
        /data/adb/modules/teesimulator \
        /data/adb/modules/teesimulator-rs \
        /data/adb/modules/playintegrityfix \
        /data/adb/modules/kpatch-next \
        /system/bin/su \
        /system/xbin/su \
        /sbin/su \
        /vendor/bin/su \
        /dev/socket/ksud; do
        [ -e "$p" ] && echo "$p"
    done

    # 配置文件里的额外路径（空格分隔）
    local extra
    extra=$(get_config PATH_HIDE_EXTRA "")
    if [ -n "$extra" ]; then
        echo "$extra" | tr ' ' '\n'
    fi

    # 用户手动添加的路径（每行一个，支持 # 注释）
    if [ -f "$USER_PATHS_FILE" ]; then
        grep -v '^[[:space:]]*#' "$USER_PATHS_FILE" 2>/dev/null \
            | grep -v '^[[:space:]]*$'
    fi
}

# 隐藏路径：避免管道子 shell 陷阱
hide_common_paths() {
    local ks="$1"
    local tmplist="$RUN_DIR/.sus_paths.tmp"
    local p

    collect_paths > "$tmplist" 2>/dev/null

    while IFS= read -r p; do
        [ -z "$p" ] && continue
        # 去尾部斜杠（SUSFS 按字符串匹配，/data/adb 和 /data/adb/ 是两条）
        p="${p%/}"
        [ -z "$p" ] && continue
        [ -e "$p" ] || continue
        # 幂等 add；失败不阻断
        "$ks" config sus_path add "$p" --loop 2>/dev/null || \
            "$ks" add_sus_path_loop "$p" 2>/dev/null || true
    done < "$tmplist"

    rm -f "$tmplist"
}

[ "$(get_config SPOOF_PATH_HIDE 1)" = "1" ] && hide_common_paths "$KS"

# ---------- 5) 可选：AVC 日志伪装 + 隐藏 SUS 挂载 ----------
[ "$(get_config SPOOF_AVC_LOG 0)" = "1" ] && {
    "$KS" config avc_log_spoofing add 2>/dev/null
    "$KS" enable_avc_log_spoofing 1 2>/dev/null
}
[ "$(get_config SPOOF_HIDE_SUS_MNTS 0)" = "1" ] && {
    "$KS" config hide_sus_mnts_for_non_su_procs add 2>/dev/null
    "$KS" hide_sus_mnts_for_non_su_procs 1 2>/dev/null
}

# ---------- 6) 可选：隐藏 Zygisk 注入库（/proc/self/maps）----------
hide_zygisk_maps() {
    local ks="$1"
    local so
    for so in \
        /data/adb/modules/rezygisk/zygisk/arm64-v8a/libzygisk.so \
        /data/adb/modules/zygisksu/zygisk/arm64-v8a/libzygisk.so \
        /data/adb/modules/zygisk-assistant/zygisk/arm64-v8a/*.so \
        /data/adb/modules/*/zygisk/arm64-v8a/*.so; do
        [ -f "$so" ] || continue
        "$ks" add_sus_map "$so" 2>/dev/null
    done
}
[ "$(get_config SUSFS_HIDE_ZYGISK_MAP 1)" = "1" ] && hide_zygisk_maps "$KS"

log 2 "susfs_fix: applied cmdline+$B"
echo "SUSFS_FIX=OK"
exit 0
