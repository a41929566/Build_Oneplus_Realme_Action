#!/system/bin/sh
# status_now.sh - 实时读 sysfs 生成 WebUI 所需的完整 status JSON
# 由 WebUI shExec 调用，不需要常驻 daemon。
#
# 字段契约：必须覆盖 webroot/index.html 实际消费的全部键，缺键会让前端渲染成
# "undefined"（例如缺 hwid.supported 时状态卡片恒显示「内核不支持」）。
# 键集合与 tools/daemon_loop.sh 的 write_status() 同构。
# 公共原语（gprop / catf / jq_s / jq_s_raw / detect_susfs / list_user_paths）
# 统一由 lib_common.sh 提供。

# 统一走 lib_common.sh 的 sysfs 路径解析（hwid 可能内建于 pkgmask）
. "$(dirname "$0")/lib_common.sh"
PKG="$PKG_SYSFS"
HWID="$HWID_SYSFS"

# ---------------- pkgmask ----------------
pmsup=0
pmscope=""; pmdeny=""; pmpaths=""; pmhproc=0; pmhname=""; pmstat=""
if [ -d "$PKG" ] && [ -f "$PKG/reload" ]; then
    pmsup=1
    pmscope=$(catf "$PKG/scope_mode")
    pmdeny=$(catf "$PKG/deny_uids")
    pmpaths=$(catf "$PKG/target_paths")
    pmhproc=$(catf "$PKG/hide_proc_enabled"); pmhproc=${pmhproc:-0}
    pmhname=$(catf "$PKG/hide_proc_names")
    pmstat=$(catf "$PKG/status" | tr '\n' ';')
fi
hperm=$(catf "$PKG/hook_perm");         hperm=${hperm:-N}
hgetattr=$(catf "$PKG/hook_getattr");   hgetattr=${hgetattr:-N}
hgetdents=$(catf "$PKG/hook_getdents"); hgetdents=${hgetdents:-N}
hdirents=$(catf "$PKG/hide_dirents");   hdirents=${hdirents:-N}
# 检测方 A / 被隐藏对象 B（空格分隔），供 WebUI 回填勾选态
tgts=$(get_config pkgmask_targets "")
hides=$(get_config pkgmask_hide_pkgs "")

# ---------------- hwid ----------------
hwsup=0; hwen=0; hwactive=0
hsoc=""; hcid=""; hcpu=""; hwmac=""; hbmac=""; hwid_uids=""
if [ -f "$HWID/hwid_enabled" ]; then
    hwsup=1
    hwen=$(catf "$HWID/hwid_enabled"); hwen=${hwen:-0}
    hwactive=$(catf "$HWID/hwid_status" | sed -n 's/.*hook_active=\([01]\).*/\1/p')
    hwactive=${hwactive:-0}
    hsoc=$(catf "$HWID/hwid_soc_serial")
    hcid=$(catf "$HWID/hwid_cid")
    hcpu=$(catf "$HWID/hwid_cpu_serial")
    hwmac=$(catf "$HWID/hwid_wlan_mac")
    hbmac=$(catf "$HWID/hwid_bt_mac")
    hwid_uids=$(catf "$HWID/hwid_uids")
fi

# ---------------- props 当前值 / 假值 ----------------
serial=$(gprop ro.serialno)
inc=$(gprop ro.build.version.incremental)
fp=$(gprop ro.build.fingerprint)
vb=$(gprop ro.boot.verifiedbootstate)
dbg=$(gprop ro.debuggable)
tags=$(gprop ro.build.tags)
oem=$(gprop sys.oem_unlock_allowed)
model=$(gprop ro.product.model)
aidcur=$(settings --user 0 get secure android_id 2>/dev/null | tr -d '\r\n')
# 假值集中在 fake_profile.conf；缺失时保持空串，避免 JSON 里出现空变量名
fake_serial=""; fake_inc=""; fake_wmac=""; fake_bmac=""
fake_soc=""; fake_cid=""; fake_cpu=""; fake_aid=""
if [ -f "$PROFILE" ]; then
    . "$PROFILE" 2>/dev/null
fi

# ---------------- susfs ----------------
susver=$(catf /sys/module/susfs/version)
if [ -n "$susver" ]; then
    susstate="ready"
elif [ -d /sys/module/susfs ] || [ -d /sys/module/ksu_susfs ]; then
    susstate="present"; susver="present"
else
    susstate="built_in_or_hidden"; susver="built-in/hidden"
fi
susfs_check=$(detect_susfs)

# ---------------- sus_path ----------------
user_paths=$(list_user_paths | tr '\n' '|' | sed 's/|$//')
sus_paths_json=$(catf "$SUSFS_JSON" | grep -o '"/[^"]*"' | tr '\n' '|' | sed 's/|$//')

# ---------------- verify / procs（缓存文件直接内联，去掉真实换行以保证 JSON 合法） ----------------
# 缓存文件缺失或半写入（内容不是合法数组）时必须回退成 []，
# 否则坏内容会被原样内联进 status JSON，前端 JSON.parse 直接抛异常、整个面板空白。
verify=$(catf "$RUN_DIR/verify_cache.json" | tr -d '\r\n')
case "$verify" in \[*\]) ;; *) verify="[]" ;; esac
procs=$(catf "$RUN_DIR/procs_cache.json" | tr -d '\r\n')
case "$procs" in \[*\]) ;; *) procs="[]" ;; esac

# ---------------- selfcheck ----------------
scp=0; scw=0; scf=0
if [ -f "$DATA_DIR/selfcheck_result.json" ]; then
    scp=$(sed -n 's/.*"pass": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
    scw=$(sed -n 's/.*"warn": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
    scf=$(sed -n 's/.*"fail": *\([0-9]*\).*/\1/p' "$DATA_DIR/selfcheck_result.json" | head -1)
fi
scp=${scp:-0}; scw=${scw:-0}; scf=${scf:-0}

# 明细来源：selfcheck.sh 写 run/selfcheck_items.tsv，格式 "状态<TAB>描述"
# 注意 awk 的一个陷阱：输入文件打不开时，awk 会先执行 BEGIN 打出 "["，
# 再因致命错误跳过 END，最终只留下一个孤立的 "["（不是空串）。
# 因此旧的 [ -z "$sc_items" ] 守卫拦不住它，会拼出 "items": [} —— 非法 JSON。
# 这里改成只接受形如 [...] 的完整结果，其余一律回退 []。
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
case "$sc_items" in \[*\]) ;; *) sc_items="[]" ;; esac

# ---------------- kernel ----------------
kver=$(uname -r 2>/dev/null)
karch=$(uname -m 2>/dev/null)

# JSON 单行字符串转义（真实换行必须去掉；多行字段请用 jq_s_raw）
# 必须用 printf 而不是 echo：echo 在 dash/ash 等 shell 下会解释反斜杠转义，
# 把值里的 "\1" 变成 0x01 控制字符 —— 控制字符在 JSON 字符串里非法，
# 会让整个 status JSON 解析失败。printf '%s' 原样输出，不解释任何转义。
esc() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'
}

# 输出 JSON 正文。这里整段用 printf 而不是 echo，原因同上：
# esc()/jq_s_raw() 已经把值转义成 JSON 需要的形式（例如 \\n、\"），
# 如果再用 echo 输出，dash/ash 会把这两个字符的转义再解释一遍，
# 结果 "\\n" 变成真换行、"\"B" 变成非法转义 \B —— 前端 JSON.parse 直接失败。
printf '%s\n' "{"
printf '%s\n' "  \"ts\": $(date +%s),"
printf '%s\n' "  \"pkgmask\": {"
printf '%s\n' "    \"supported\": \"$pmsup\","
printf '%s\n' "    \"scope\": \"$(esc "$pmscope")\","
printf '%s\n' "    \"deny_uids\": \"$(esc "$pmdeny")\","
printf '%s\n' "    \"target_paths\": \"$(esc "$pmpaths")\","
printf '%s\n' "    \"hide_proc\": $pmhproc,"
printf '%s\n' "    \"hide_proc_names\": \"$(esc "$pmhname")\","
printf '%s\n' "    \"status\": \"$(esc "$pmstat")\","
printf '%s\n' "    \"hook_perm\": \"$hperm\","
printf '%s\n' "    \"hook_getattr\": \"$hgetattr\","
printf '%s\n' "    \"hook_getdents\": \"$hgetdents\","
printf '%s\n' "    \"hide_dirents\": \"$hdirents\","
printf '%s\n' "    \"targets\": \"$(esc "$tgts")\","
printf '%s\n' "    \"hide_pkgs\": \"$(esc "$hides")\""
printf '%s\n' "  },"
printf '%s\n' "  \"hwid\": {"
printf '%s\n' "    \"supported\": \"$hwsup\","
printf '%s\n' "    \"enabled\": \"$hwen\","
printf '%s\n' "    \"hook_active\": \"$hwactive\","
printf '%s\n' "    \"uids\": \"$(esc "$hwid_uids")\","
printf '%s\n' "    \"cur_aid\": \"$(esc "$aidcur")\","
printf '%s\n' "    \"fake_aid\": \"$(esc "$fake_aid")\","
printf '%s\n' "    \"soc\": \"$(esc "$hsoc")\","
printf '%s\n' "    \"fake_soc\": \"$(esc "$fake_soc")\","
printf '%s\n' "    \"cid\": \"$(esc "$hcid")\","
printf '%s\n' "    \"fake_cid\": \"$(esc "$fake_cid")\","
printf '%s\n' "    \"cpu\": \"$(esc "$hcpu")\","
printf '%s\n' "    \"fake_cpu\": \"$(esc "$fake_cpu")\","
printf '%s\n' "    \"wmac\": \"$(esc "$hwmac")\","
printf '%s\n' "    \"fake_wmac\": \"$(esc "$fake_wmac")\","
printf '%s\n' "    \"bmac\": \"$(esc "$hbmac")\","
printf '%s\n' "    \"fake_bmac\": \"$(esc "$fake_bmac")\""
printf '%s\n' "  },"
printf '%s\n' "  \"susfs\": {\"version\": \"$(esc "$susver")\", \"state\": \"$susstate\", \"check\": \"$(jq_s_raw "$susfs_check")\"},"
printf '%s\n' "  \"sus_path\": {\"user\": \"$(esc "$user_paths")\", \"registered\": \"$(esc "$sus_paths_json")\"},"
printf '%s\n' "  \"props\": {"
printf '%s\n' "    \"serial\": \"$(esc "$serial")\","
printf '%s\n' "    \"fake_serial\": \"$(esc "$fake_serial")\","
printf '%s\n' "    \"incremental\": \"$(esc "$inc")\","
printf '%s\n' "    \"fake_inc\": \"$(esc "$fake_inc")\","
printf '%s\n' "    \"fingerprint\": \"$(esc "$fp")\","
printf '%s\n' "    \"vbstate\": \"$(esc "$vb")\","
printf '%s\n' "    \"debuggable\": \"$(esc "$dbg")\","
printf '%s\n' "    \"tags\": \"$(esc "$tags")\","
printf '%s\n' "    \"oem\": \"$(esc "$oem")\","
printf '%s\n' "    \"model\": \"$(esc "$model")\""
printf '%s\n' "  },"
printf '%s\n' "  \"kernel\": {\"version\": \"$(esc "$kver")\", \"arch\": \"$(esc "$karch")\"},"
printf '%s\n' "  \"selfcheck\": {\"pass\": $scp, \"warn\": $scw, \"fail\": $scf, \"items\": $sc_items},"
printf '%s\n' "  \"verify\": $verify,"
printf '%s\n' "  \"procs\": $procs"
printf '%s\n' "}"
#（注：内容由AI生成）
