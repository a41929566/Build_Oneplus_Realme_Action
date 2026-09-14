#!/system/bin/sh
# SUSFS环境守护 v6.2 - AppOps：管理检测方的查询应用列表权限
# Maple 等的“三方环境检测”走 PM/Binder(getInstalledPackages)，readdir/SUSFS 挡不住；
# 撤销 QUERY_ALL_PACKAGES 后，系统只返回带 <queries> 可见的有限包，MT 等不可见。
#
# 用法: appops_setup.sh {apply|restore}

. "${0%/*}/lib_common.sh"

OPS="QUERY_ALL_PACKAGES GET_USAGE_STATS"
APPOPS_BACKUP="$BACKUP_DIR/appops"

mkdir -p "$APPOPS_BACKUP"

read_state() {
    local pkg=$1 op=$2 state
    state=$(appops get "$pkg" "$op" 2>/dev/null | tail -1 | sed -n 's/.*: \([a-z_]*\).*/\1/p')
    case "$state" in
        allow|deny|ignore|foreground|default|errored|ask) echo "$state" ;;
        *) echo default ;;
    esac
}

read_uid_state() {
    local uid=$1 op=$2 state
    state=$(appops get --uid "$uid" "$op" 2>/dev/null | tail -1 | sed -n 's/.*: \([a-z_]*\).*/\1/p')
    case "$state" in
        allow|deny|ignore|foreground|default|errored|ask) echo "$state" ;;
        *) echo default ;;
    esac
}

do_apply() {
    local targets p uid op key
    targets=$(get_config pkgmask_targets "")
    for p in $targets; do
        # 优先按包名设置（现代 appops 支持），再按 uid 兜底
        for op in $OPS; do
            key=$(printf '%s_%s' "$p" "$op" | tr '.-' '__')
            backup_once "appops_${key}" "$(read_state "$p" "$op")"
            appops set "$p" "$op" ignore 2>/dev/null
        done
        uid=$(pkg_uid "$p")
        if [ -n "$uid" ]; then
            for op in $OPS; do
                key=$(printf '%s_%s' "$uid" "$op" | tr '.-' '__')
                backup_once "appops_uid_${key}" "$(read_uid_state "$uid" "$op")"
                appops set --uid "$uid" "$op" ignore 2>/dev/null
            done
            log 2 "appops: $p($uid) QUERY_ALL_PACKAGES=ignore"
        fi
    done
}

do_restore() {
    local targets p uid op key state
    targets=$(get_config pkgmask_targets "")
    for p in $targets; do
        for op in $OPS; do
            key=$(printf '%s_%s' "$p" "$op" | tr '.-' '__')
            state=$(backup_read "appops_${key}")
            [ -n "$state" ] && appops set "$p" "$op" "$state" 2>/dev/null
        done
        uid=$(pkg_uid "$p")
        if [ -n "$uid" ]; then
            for op in $OPS; do
                key=$(printf '%s_%s' "$uid" "$op" | tr '.-' '__')
                state=$(backup_read "appops_uid_${key}")
                [ -n "$state" ] && appops set --uid "$uid" "$op" "$state" 2>/dev/null
            done
            log 2 "appops restored: $p($uid)"
        fi
    done
}

case "$1" in
    apply) do_apply ;;
    restore) do_restore ;;
    *) echo "usage: $0 {apply|restore}" ;;
esac
