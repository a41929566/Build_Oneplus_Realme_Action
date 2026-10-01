#!/system/bin/sh
# SUSFS环境守护 v6.3 - pkgmask 真 sysfs 配置
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

# 构建"系统信号文件"隐藏列表（只对 deny_uids 里的检测方生效）
# 精简列表：避免超过内核 MAX_HIDE_TARGETS（64），当前 7 条最关键的
build_extra_paths() {
    local out="" p
    for p in \
        /proc/kallsyms \
        /proc/config.gz \
        /proc/modules \
        /sys/block/sda/queue/scheduler \
        /sys/module/rezygisk \
        /sys/module/zygisk_assistant \
        /proc/device-tree/soc/oplus,hmbird; do
        [ -e "$p" ] && out="${out:+$out,}$p"
    done
    local user_extra
    user_extra=$(get_config pkgmask_extra_paths "")
    if [ -n "$user_extra" ]; then
        out="${out:+$out,}$user_extra"
    fi
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
    local deny paths procs mode extra
    deny=$(build_deny_uids)
    paths=$(build_target_paths)
    extra=$(build_extra_paths)
    procs=$(build_hide_procs)
    mode=$(get_config pkgmask_scope deny)

    # 合并敏感路径：包名路径 + 系统信号文件路径
    if [ -n "$extra" ]; then
        paths="${paths:+$paths,}$extra"
    fi

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
    # === allow_uids：与上方 deny_uids 采用同样的空值保护 ===
    # 本模块没有 allow 名单的来源（全仓唯一引用点就是这里），无条件写入空串
    # 只会清掉内核里已有的白名单配置。默认 scope=deny 时该键本就不参与判定。
    local alw
    alw=$(get_config pkgmask_allow_uids "")
    if [ -n "$alw" ]; then
        w allow_uids "$alw"
    else
        log 1 "pkgmask: allow_uids 无来源，跳过写入（保留内核已有配置）"
    fi
    if [ -n "$paths" ]; then
        # 内核 MAX_HIDE_TARGETS=64，超出部分会被静默丢弃 —— 必须显式告警，
        # 否则 selfcheck 只看「target_paths 已配置」照样 PASS，给用户虚假信心。
        #
        # 【为什么不能只数逗号条数】内核 add_target_path() 会为
        # /data/data/X 自动追加别名 /data/user/0/X，反之亦然
        # （见 patch/patch/pkgmask/pkgmask.c 的 alias 分支）。即这两个前缀的
        # 每一条实际占 2 个槽位。而 build_target_paths() 每个被隐藏包产出 3 条：
        #   /data/data/X(2) + /data/user/0/X(2) + /data/user_de/0/X(1) = 5 槽/包
        # 旧阈值只比较「逗号条数 > 64」（约 20 个包才告警），真实上限却是
        # ~11 个包（扣除 build_extra_paths 的约 7 条）。中间 9 个包的隐藏会被
        # 内核静默丢弃而脚本毫无提示。这里按别名展开后的真实槽位计数。
        local np n_alias
        np=$(printf '%s' "$paths" | tr ',' '\n' | grep -c .)
        n_alias=$(printf '%s' "$paths" | tr ',' '\n' \
                  | grep -c -e '^/data/data/' -e '^/data/user/0/')
        np=$((np + n_alias))
        [ "$np" -gt 64 ] && \
            log 0 "pkgmask: target_paths 展开别名后占用内核槽位 $np（上限 64），超出部分会被静默丢弃！请减少隐藏目标（每个包占 5 槽，实际上限约 11 个包）"
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

    # 合并到 hidden_procs.txt，避免 process_hide.sh 的 do_apply 清空内核
    # 用户通过 WebUI 手动添加的进程不会被覆盖
    if [ -n "$procs" ]; then
        local PROC_CONF="$DATA_DIR/hidden_procs.txt"
        touch "$PROC_CONF" 2>/dev/null
        echo "$procs" | tr ',' '\n' | while IFS= read -r _p; do
            [ -z "$_p" ] && continue
            grep -qxF "$_p" "$PROC_CONF" 2>/dev/null || echo "$_p" >> "$PROC_CONF"
        done
        log 2 "pkgmask: merged hide_proc_names into hidden_procs.txt"
    fi

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
    if ! pm_supported; then printf '%s\n' '{ "supported":"0" }'; return; fi
    # 所有取值都过 jq_s（lib_common.sh 提供）：target_paths / hide_proc_names 这类
    # 内容可能含引号或反斜杠，直接内联会产出非法 JSON，导致 WebUI 解析失败。
    # 输出一律用 printf：jq_s 已把反斜杠转义成 \\，若再用 echo，dash/ash 会
    # 把这两个字符的转义再解释一遍，结果 \\n 变真换行、\\1 变非法转义 \1。
    printf '%s\n' "{"
    printf '%s\n' "  \"supported\": \"1\","
    printf '%s\n' "  \"scope\": \"$(jq_s "$(cat "$PM/scope_mode" 2>/dev/null)")\","
    printf '%s\n' "  \"deny_uids\": \"$(jq_s "$(cat "$PM/deny_uids" 2>/dev/null)")\","
    printf '%s\n' "  \"target_paths\": \"$(jq_s "$(cat "$PM/target_paths" 2>/dev/null)")\","
    printf '%s\n' "  \"hide_proc\": \"$(jq_s "$(cat "$PM/hide_proc_enabled" 2>/dev/null)")\","
    printf '%s\n' "  \"hide_proc_names\": \"$(jq_s "$(cat "$PM/hide_proc_names" 2>/dev/null)")\","
    printf '%s\n' "  \"hook_getdents\": \"$(jq_s "$(cat "$PM/hook_getdents" 2>/dev/null)")\","
    printf '%s\n' "  \"hook_perm\": \"$(jq_s "$(cat "$PM/hook_perm" 2>/dev/null)")\","
    printf '%s\n' "  \"status\": \"$(jq_s "$(cat "$PM/status" 2>/dev/null | tr '\n' ';')")\""
    printf '%s\n' "}"
}

case "$1" in
    apply) do_apply ;;
    restore) do_restore ;;
    status) do_status ;;
    *) echo "usage: $0 {apply|restore|status}" ;;
esac
