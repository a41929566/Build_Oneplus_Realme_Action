#!/system/bin/sh
# SUSFS Env Guard - identity_ids.sh（非属性类 ID：SSAID / GSF / AppSet）
#
# 【说明】属性类身份（机型/品牌/构建号）请用 device_model.sh 处理。
#   本文件只管「不走 ro.* 属性」的那几个 ID —— 它们存在数据库或 XML 里。
#
# 【开关】(写在 spoof.conf，默认全部 0 = 关闭，绝不自动破坏数据)
#   ids_ssaid_reset=1   重置 SSAID（移走存储文件，系统会重新生成随机值）
#   ids_gsf_reset=1     改 GSF ID（优先 sqlite 改写；失败日志提示）
#   ids_gsf_value=xxx   指定 GSF ID（16 位 hex），留空则随机生成
#   ids_gms_clear=1     【破坏性】清 Google 服务框架/GMS 数据，用于彻底换 GSF/AppSet
#                       副作用：Google 账户需重新登录，仅在你确认后手动开启
#
# 【用法】identity_ids.sh {apply|restore|status|detect}

. "${0%/*}/lib_common.sh"

II_FLAG="$DATA_DIR/identity_ids_applied"
GSF_DB="/data/data/com.google.android.gsf/databases/gservices.db"

# ---------- SSAID ----------
# Android 8+ 每用户每应用 SSAID 存放位置（不同版本路径略有差异）
ssaid_paths() {
    for _p in /data/system/users/*/settings_ssaid.xml \
              /data/system/users/0/settings_ssaid.xml \
              /data/system/0/settings_ssaid.xml; do
        [ -e "$_p" ] && echo "$_p"
    done
}

do_ssaid_reset() {
    local p n=0
    for p in $(ssaid_paths); do
        # 改名为 .bak 而不是删除：万一需要可手动恢复
        if mv -f "$p" "${p}.bak.$(date +%s 2>/dev/null)" 2>/dev/null; then
            n=$((n + 1))
            log 2 "identity_ids: ssaid reset -> $p"
        fi
    done
    if [ "$n" -gt 0 ]; then
        echo "SSAID=RESET($n)"
        log 2 "identity_ids: SSAID 已重置，App 下次查询时会得到新的随机值（可能需要重启）"
    else
        echo "SSAID=NO_FILE(未找到存储文件，本机型可能不走该路径)"
    fi
}

# ---------- GSF ID ----------
gsf_target_value() {
    local v
    v=$(get_config ids_gsf_value "")
    if [ -z "$v" ]; then
        v=$(rand_hex 8)
    fi
    # 只保留 hex，防 SQL 注入 / 非法字符
    echo "$v" | tr -cd '0-9a-fA-F'
}

do_gsf_reset() {
    local v
    # 优先自杀式清数据（用户显式开启且确认过副作用）
    if [ "$(get_config ids_gms_clear 0)" = "1" ]; then
        log 0 "identity_ids: ids_gms_clear=1，正在清空 Google 服务框架数据（会退出 Google 登录）"
        timeout 20 pm clear com.google.android.gsf 2>/dev/null
        echo "GSF=CLEARED(com.google.android.gsf)"
        return 0
    fi

    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "GSF=UNSUPPORTED(无 sqlite3)"
        log 1 "identity_ids: 系统无 sqlite3，无法改写 GSF ID；如需可开启 ids_gms_clear=1"
        return 1
    fi
    if [ ! -f "$GSF_DB" ]; then
        echo "GSF=NO_DB($GSF_DB 不存在)"
        log 1 "identity_ids: 未找到 gservices.db，新版 GMS 可能已换存储；可开启 ids_gms_clear=1"
        return 1
    fi

    v=$(gsf_target_value)
    [ -n "$v" ] || { echo "GSF=EMPTY_VALUE"; return 1; }

    if timeout 10 sqlite3 "$GSF_DB" \
        "UPDATE main SET value='$v' WHERE name='android_id';" 2>/dev/null; then
        echo "GSF=OK($v)"
        log 2 "identity_ids: GSF android_id 已改写为 $v"
    else
        echo "GSF=SQL_FAILED"
        log 1 "identity_ids: sqlite 改写失败（表结构可能已变）"
    fi
}

# ---------- AppSet / GSF 大清洗 ----------
# 【破坏性】清空 Google 服务框架 + GMS 数据 → GSF ID / AppSet ID 全部重新生成
# 副作用：Google 账号会被登出，需重新登录。仅由 WebUI 显式点按钮触发。
do_appset_reset() {
    log 0 "identity_ids: 正在清空 Google 服务框架/GMS 数据（会退出 Google 登录）"
    timeout 30 pm clear com.google.android.gsf 2>/dev/null
    timeout 30 pm clear com.google.android.gms 2>/dev/null
    echo "APPSET=GMS_CLEARED(需重新登录 Google)"
}

# ---------- 检测报告（只读，绝不修改） ----------
do_detect() {
    echo "=== 已装的广告/标识相关服务 ==="
    for pkg in com.huawei.hwid com.huawei.android.hwouc \
               com.android.creator com.oplus.oaid \
               com.google.android.gms com.google.android.gsf \
               com.android.vending; do
        if [ -d "/data/data/$pkg" ]; then
            echo "  已安装: $pkg"
        fi
    done
    echo
    echo "=== SSAID 存储文件 ==="
    ssaid_paths | while IFS= read -r p; do echo "  $p"; done
    echo
    echo "=== GSF 数据库 ==="
    [ -f "$GSF_DB" ] && echo "  存在: $GSF_DB" || echo "  不存在: $GSF_DB"
    command -v sqlite3 >/dev/null 2>&1 && echo "  sqlite3: 可用" || echo "  sqlite3: 不可用"
}

do_apply() {
    init_feature_flags
    : > "$II_FLAG" 2>/dev/null

    if [ "$(get_config ids_ssaid_reset 0)" = "1" ]; then
        do_ssaid_reset
    else
        echo "SSAID=SKIPPED"
    fi

    if [ "$(get_config ids_gsf_reset 0)" = "1" ]; then
        do_gsf_reset
    else
        echo "GSF=SKIPPED"
    fi

    echo "IDENTITY_IDS=DONE"
}

do_status() {
    # 与 device_model.sh dm_status() 同规范：值过 jq_s()，输出用 printf。
    # 本函数同样由 WebUI 直接 JSON.parse，echo 在 dash/ash 下会二次解释
    # 反斜杠转义，产出的 JSON 会被前端静默丢弃（卡片显示 "–" 且无报错）。
    printf '%s\n' "{"
    printf '%s\n' "  \"ssaid_reset\": \"$(jq_s "$(get_config ids_ssaid_reset 0)")\","
    printf '%s\n' "  \"gsf_reset\": \"$(jq_s "$(get_config ids_gsf_reset 0)")\","
    printf '%s\n' "  \"gms_clear\": \"$(jq_s "$(get_config ids_gms_clear 0)")\","
    printf '%s\n' "  \"applied\": \"$([ -f "$II_FLAG" ] && printf yes || printf no)\""
    printf '%s\n' "}"
}

case "$1" in
    # 供 run.sh 开机自动调用（按 spoof.conf 开关）
    apply)   do_apply ;;
    # 供 WebUI 按钮一次性触发（不写开关，避免每次开机重复重置）
    ssaid)   do_ssaid_reset ;;
    gsf)     do_gsf_reset ;;
    appset)  do_appset_reset ;;
    status)  do_status ;;
    detect)  do_detect ;;
    restore) echo "SSAID/GSF 为一次性写操作，卸载时请用 .bak 备份手动恢复" ;;
    *)       echo "usage: $0 {apply|ssaid|gsf|appset|restore|status|detect}" ;;
esac
