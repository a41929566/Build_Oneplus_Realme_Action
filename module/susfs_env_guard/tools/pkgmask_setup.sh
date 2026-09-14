#!/system/bin/sh
# SUSFS环境守护 v6.2 - pkgmask 真 sysfs 配置
# 驱动真实接口（pkgmask v4.9，built-in，CONFIG_PKGMASK=y）：
#   deny_uids(逗号分隔)  scope_mode=deny  target_paths(逗号分隔)
#   hide_dirents/hook_getdents/hook_perm/hook_getattr=1
#   hide_proc_enabled=1  hide_proc_names(逗号分隔 task->comm)  reload=1  status(只读)
# 语义：对 deny_uids 中的进程(A=检测方)，在 readdir/stat/open 层隐藏 target_paths(B)。
#
# 用法: pkgmask_setup.sh {apply|restore|status}

. "${0%/*}/lib_common.sh"

PM="$PKG_SYSFS"
PMC="/data/adb/pkgmask"
mkdir -p "$PMC" 2>/dev/null

pm_supported() { [ -d "$PKG_SYSFS" ] && [ -f "$PKG_SYSFS/reload" ]; }

w() { # w <node> <val>  存在且可写才写
    [ -e "$PM/$1" ] && echo "$2" > "$PM/$1" 2>/dev/null
}

build_deny_uids() {
    local targets out="" p uid
    targets=$(get_config pkgmask_targets "")
    for p in $targets; do
        uid=$(pkg_uid "$p")
        # === 修复4：UID 获取失败时重试一次（boot_completed 前 system_server 可能未就绪） ===
        if [ -z "$uid" ] && [ "$(getprop sys.boot_completed)" != "1" ]; then
            sleep 5
            uid=$(pkg_uid "$p")
        fi
        if [ -n "$uid" ]; then
            # 去重（多检测方可能共享 uid）
            case ",$out," in *",$uid,"*) ;; *) out="${out:+$out,}$uid";; esac
        else
            log 1 "pkgmask: 检测方 $p 未安装/取不到uid"
        fi
    done
    echo "$out"
}

build_target_paths() {
    local hides out="" p
    hides=$(get_config pkgmask_hide_pkgs "")
    for p in $hides; do
        out="${out:+$out,}/data/data/$p,/data/user/0/$p,/data/user_de/0/$p"
    done
    echo "$out"
}

build_hide_procs() {
    # task->comm 最长 15 字符；主进程 comm 通常等于包名，这里截断到 15
    local procs out="" p c
    procs=$(get_config pkgmask_hide_procs "$(get_config pkgmask_hide_pkgs '')")
    for p in $procs; do
        c=$(echo "$p" | cut -c1-15)
        out="${out:+$out,}$c"
    done
    echo "$out"
}

do_apply() {
    if ! pm_supported; then
        log 1 "pkgmask 内核节点缺失（需 CONFIG_PKGMASK=y 的内核），跳过"
        echo "PKGMASK=UNSUPPORTED"; return 1
    fi
    local deny paths procs mode
    deny=$(build_deny_uids)
    paths=$(build_target_paths)
    procs=$(build_hide_procs)
    mode=$(get_config pkgmask_scope deny)

    # 顺序：先数据，后模式/开关，最后 reload
    w hide_dirents 1
    w hook_getdents 1
    w hook_perm 1
    w hook_getattr 1
    # === 修复4：空值保护——deny_uids 为空时不写入，避免清空内核已有配置 ===
    if [ -n "$deny" ]; then
        w deny_uids "$deny"
    else
        log 1 "pkgmask: deny_uids 为空，跳过写入（保留内核已有配置）"
    fi
    w allow_uids ""
    if [ -n "$paths" ]; then
        w target_paths "$paths"
    else
        log 1 "pkgmask: target_paths 为空，跳过写入"
    fi
    w scope_mode "$mode"
    [ -n "$procs" ] && { w hide_proc_enabled 1; w hide_proc_names "$procs"; }
    w reload 1

    # 落盘纯文本（刷机/守护重放用，不依赖 WebUI）
    {
        echo "# pkgmask runtime config $(date)"
        echo "deny_uids=$deny"
        echo "target_paths=$paths"
        echo "scope_mode=$mode"
        echo "hide_proc_names=$procs"
    } > "$PMC/config.conf"

    log 2 "pkgmask applied deny=[$deny] paths#=$(echo "$paths" | tr ',' '\n' | grep -c data)"
    echo "PKGMASK=OK"
    do_status
}

do_restore() {
    pm_supported || return 0
    w deny_uids ""
    w target_paths ""
    w hide_proc_enabled 0
    w hide_proc_names ""
    w scope_mode global
    w reload 1
    log 2 "pkgmask rules cleared"
}

do_status() {
    if ! pm_supported; then echo '{ "supported":"0" }'; return; fi
    echo "{"
    echo "  \"supported\": \"1\","
    echo "  \"scope\": \"$(cat "$PM/scope_mode" 2>/dev/null)\","
    echo "  \"deny_uids\": \"$(cat "$PM/deny_uids" 2>/dev/null)\","
    echo "  \"target_paths\": \"$(cat "$PM/target_paths" 2>/dev/null)\","
    echo "  \"hide_proc\": \"$(cat "$PM/hide_proc_enabled" 2>/dev/null)\","
    echo "  \"hide_proc_names\": \"$(cat "$PM/hide_proc_names" 2>/dev/null)\","
    echo "  \"hook_getdents\": \"$(cat "$PM/hook_getdents" 2>/dev/null)\","
    echo "  \"hook_perm\": \"$(cat "$PM/hook_perm" 2>/dev/null)\","
    echo "  \"status\": \"$(cat "$PM/status" 2>/dev/null | tr '\n' ';')\""
    echo "}"
}

case "$1" in
    apply) do_apply ;;
    restore) do_restore ;;
    status) do_status ;;
    *) echo "usage: $0 {apply|restore|status}" ;;
esac