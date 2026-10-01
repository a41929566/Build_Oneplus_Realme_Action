#!/system/bin/sh
# SUSFS环境守护 v6.3 - AppOps：管理检测方的查询应用列表权限
# Maple 等的“三方环境检测”走 PM/Binder(getInstalledPackages)，readdir/SUSFS 挡不住；
# 撤销 QUERY_ALL_PACKAGES 后，系统只返回带 <queries> 可见的有限包，MT 等不可见。
#
# 用法: appops_setup.sh {apply|restore}

. "${0%/*}/lib_common.sh"

OPS="QUERY_ALL_PACKAGES GET_USAGE_STATS"
APPOPS_BACKUP="$BACKUP_DIR/appops"
# 备份索引：kind<TAB>id<TAB>op<TAB>原状态
# 【为什么需要索引】旧实现把备份文件名拼成 appops_<pkg>_<op>（. 和 - 都换成 _），
# 这是不可逆的（com.foo-bar 与 com.foo.bar 会撞同一个文件名），而且 do_restore
# 只遍历「当前 pkgmask_targets」——用户一旦把某个检测方从 A 列表里删掉，
# 它的 appops 状态就永远不会被还原，备份文件也永久残留。索引把 id/op 原样存下来，
# 使还原可以独立于当前配置、按备份全集进行。
APPOPS_INDEX="$APPOPS_BACKUP/index.tsv"

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

# backup_op <pkg|uid> <id> <op> <state> —— 同一 (kind,id,op) 只记一次原始值
backup_op() {
    local kind=$1 id=$2 op=$3 state=$4
    [ -n "$id" ] || return 0
    [ -n "$state" ] || state=default
    touch "$APPOPS_INDEX" 2>/dev/null
    # 用 TAB 分隔精确匹配，避免 pkg 前缀互相误判
    grep -qF "$(printf '%s\t%s\t%s\t' "$kind" "$id" "$op")" "$APPOPS_INDEX" 2>/dev/null && return 0
    printf '%s\t%s\t%s\t%s\n' "$kind" "$id" "$op" "$state" >> "$APPOPS_INDEX" 2>/dev/null
}

do_apply() {
    local targets p uid op state
    targets=$(get_config pkgmask_targets "")
    for p in $targets; do
        # 优先按包名设置（现代 appops 支持），再按 uid 兜底
        for op in $OPS; do
            state=$(read_state "$p" "$op")
            backup_op pkg "$p" "$op" "$state"
            appops set "$p" "$op" ignore 2>/dev/null
        done
        uid=$(pkg_uid "$p")
        if [ -n "$uid" ]; then
            for op in $OPS; do
                state=$(read_uid_state "$uid" "$op")
                backup_op uid "$uid" "$op" "$state"
                appops set --uid "$uid" "$op" ignore 2>/dev/null
            done
            log 2 "appops: $p($uid) QUERY_ALL_PACKAGES=ignore"
        fi
    done
}

do_restore() {
    local kind id op state n=0
    # 按备份全集还原，而不是按「当前 pkgmask_targets」——否则被移出 A 列表的
    # 包永远恢复不了权限（这正是旧实现的缺陷）。
    if [ -f "$APPOPS_INDEX" ]; then
        while IFS='	' read -r kind id op state; do
            [ -z "$id" ] && continue
            [ -z "$op" ] && continue
            [ -z "$state" ] && state=default
            if [ "$kind" = "uid" ]; then
                appops set --uid "$id" "$op" "$state" 2>/dev/null && n=$((n + 1))
            else
                appops set "$id" "$op" "$state" 2>/dev/null && n=$((n + 1))
            fi
        done < "$APPOPS_INDEX"
        rm -f "$APPOPS_INDEX" 2>/dev/null
        log 2 "appops restored from index: $n entries"
        echo "APPOPS_RESTORED=$n"
        return 0
    fi

    # 兼容路径：没有索引（旧版本留下的备份）时，只能按当前 A 列表尽力还原，
    # 并明确告知用户旧格式备份不可逆、可能残留。
    local targets p uid
    targets=$(get_config pkgmask_targets "")
    for p in $targets; do
        for op in $OPS; do
            state=$(backup_read "appops_$(printf '%s_%s' "$p" "$op" | tr '.-' '__')")
            [ -n "$state" ] && appops set "$p" "$op" "$state" 2>/dev/null
        done
        uid=$(pkg_uid "$p")
        if [ -n "$uid" ]; then
            for op in $OPS; do
                state=$(backup_read "appops_uid_$(printf '%s_%s' "$uid" "$op" | tr '.-' '__')")
                [ -n "$state" ] && appops set --uid "$uid" "$op" "$state" 2>/dev/null
            done
            log 2 "appops restored (legacy): $p($uid)"
        fi
    done
    if ls "$APPOPS_BACKUP"/appops_* >/dev/null 2>&1; then
        log 0 "appops: 检测到旧格式备份文件，文件名不可逆（. 与 - 均被替换为 _），无法自动还原其对应包；如需彻底恢复请对相关包执行 appops set <包名> QUERY_ALL_PACKAGES default"
    fi
}

case "$1" in
    apply) do_apply ;;
    restore) do_restore ;;
    *) echo "usage: $0 {apply|restore}" ;;
esac
