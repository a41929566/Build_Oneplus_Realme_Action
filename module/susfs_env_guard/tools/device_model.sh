#!/system/bin/sh
# SUSFS Env Guard - device_model.sh（一键改机型 · 分层安全版）
#
# 【设计原则】
#   ① 绝不在 zygote 前写 ro.boot.*  → 由调用方保障（run.sh 在 boot_completed 后调用）
#   ② 分层：[identity] 外观身份层，默认应用；[deep] 平台/SoC/HAL 层，默认关闭
#   ③ 可完整还原：每次 apply 记录属性原始真值，restore 逐个删除 resetprop 覆盖
#
# 【开关】(写在 spoof.conf)
#   device_model_enabled=1    总开关（默认 0 关闭）
#   device_model_deep=1       危险层开关（默认 0，强烈不建议开启）
#   device_model_profile=xxx  档案文件名（默认 device_profile.conf）
#
# 【用法】device_model.sh {apply|restore|status|show}

. "${0%/*}/lib_common.sh"

DM_NAME="$(get_config device_model_profile device_profile.conf)"
DM_PROFILE=""
for _c in "$MODDIR/config/$DM_NAME" "$MODDIR/config/device/$DM_NAME"; do
    [ -f "$_c" ] && { DM_PROFILE="$_c"; break; }
done
DM_BACKUP="$BACKUP_DIR/device_model_orig.conf"
DM_TMP="$BACKUP_DIR/device_model.tmp"

# 单次流式读取档案，按分层过滤输出 "key=value"
# $1 = deep 开关值（1 时才输出 [deep] 段）
# 说明：刻意不使用 "read || [ -n \"$line\" ]" 兜底写法——read 读到 EOF 失败时
#       $line 会保留上一次的值，某些 shell 下会导致 [ -n ] 永远为真而死循环。
dm_stream() {
    local deep="$1" cur="" line key val
    [ -n "$DM_PROFILE" ] && [ -f "$DM_PROFILE" ] || return 1
    while IFS= read -r line; do
        case "$line" in
            '[identity]'*) cur=identity; continue ;;
            '[deep]'*)     cur=deep;     continue ;;
            '#'*) continue ;;
            '')   continue ;;
        esac
        case "$cur" in
            identity) ;;
            deep)     [ "$deep" = "1" ] || continue ;;
            *)        continue ;;
        esac
        case "$line" in
            *=*)
                # 直接取 key：档案由脚本生成，key 无前后空格，故不做 trim
                #（刻意不用 $(echo ...) 去空白——每次都要 fork 一个子 shell，成本高）
                key=${line%%=*}
                val=${line#*=}
                [ -n "$key" ] && printf '%s=%s\n' "$key" "$val"
                ;;
        esac
    done < "$DM_PROFILE"
}

dm_apply() {
    local on deep line key val n=0 seen="" bkline

    on=$(get_config device_model_enabled 0)
    if [ "$on" != "1" ]; then
        echo "DEVICEMODEL=SKIPPED(disabled)"
        return 0
    fi
    if [ -z "$DM_PROFILE" ]; then
        log 0 "device_model: 未找到档案 $DM_NAME（检查 config/ 目录）"
        echo "DEVICEMODEL=FAILED(profile_missing)"
        return 1
    fi

    deep=$(get_config device_model_deep 0)
    [ "$deep" = "1" ] && log 2 "device_model: 危险层 [deep] 已启用（平台/SoC/HAL 覆盖，风险自负）"
    dm_stream "$deep" > "$DM_TMP" 2>/dev/null

    [ -s "$DM_TMP" ] || { log 0 "device_model: 档案为空"; echo "DEVICEMODEL=FAILED(empty)"; return 1; }
    mkdir -p "$BACKUP_DIR" 2>/dev/null
    [ -f "$DM_BACKUP" ] || : > "$DM_BACKUP" 2>/dev/null

    # 已备份的 key 读入内存（纯 shell 循环，0 fork），避免每个 key 调一次 grep
    if [ -f "$DM_BACKUP" ]; then
        while IFS= read -r bkline; do
            [ -n "$bkline" ] && seen="$seen:$bkline:"
        done < "$DM_BACKUP"
    fi

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        key=${line%%=*}
        val=${line#*=}
        [ -n "$key" ] || continue

        # 只记录还没备份过的 key；二次开机不会把伪装值当成原始值写入
        case "$seen" in
            *":${key}:"*) ;;
            *)
                printf '%s\n' "$key" >> "$DM_BACKUP" 2>/dev/null
                seen="${seen}${key}:"
                ;;
        esac
        rp_set "$key" "$val"
        n=$((n + 1))
    done < "$DM_TMP"

    rm -f "$DM_TMP" 2>/dev/null
    log 2 "device_model: applied $n props from $DM_NAME (deep=$deep)"
    echo "DEVICEMODEL=OK(applied=$n)"
}

dm_restore() {
    local line key n=0
    if [ ! -f "$DM_BACKUP" ]; then
        echo "DEVICEMODEL=NOTHING_TO_RESTORE"
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        key=${line%%=*}
        [ -n "$key" ] || continue
        rp_del "$key"
        n=$((n + 1))
    done < "$DM_BACKUP"
    rm -f "$DM_BACKUP" 2>/dev/null
    log 2 "device_model: restored $n props"
    echo "DEVICEMODEL=RESTORED($n)"
}

dm_status() {
    echo "{"
    echo "  \"enabled\": \"$(get_config device_model_enabled 0)\","
    echo "  \"deep\": \"$(get_config device_model_deep 0)\","
    echo "  \"profile\": \"$DM_NAME\","
    echo "  \"applied\": \"$([ -f "$DM_BACKUP" ] && echo yes || echo no)\","
    echo "  \"brand\": \"$(getprop ro.product.brand 2>/dev/null)\","
    echo "  \"model\": \"$(getprop ro.product.model 2>/dev/null)\","
    echo "  \"device\": \"$(getprop ro.product.device 2>/dev/null)\","
    echo "  \"marketing\": \"$(getprop ro.config.marketing_name 2>/dev/null)\","
    echo "  \"display_id\": \"$(getprop ro.build.display.id 2>/dev/null)\""
    echo "}"
}

dm_show() {
    if [ -z "$DM_PROFILE" ]; then echo "档案缺失: $DM_NAME"; return 1; fi
    echo "=== $DM_PROFILE ==="
    echo "    [identity] 默认应用；[deep] 仅当 device_model_deep=1 应用"
    cat "$DM_PROFILE" 2>/dev/null
}

case "$1" in
    apply)   dm_apply ;;
    restore) dm_restore ;;
    status)  dm_status ;;
    show)    dm_show ;;
    *)       echo "usage: $0 {apply|restore|status|show}" ;;
esac
