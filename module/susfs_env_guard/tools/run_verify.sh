#!/system/bin/sh
# SUSFS Env Guard v3.0 - run_verify.sh（应用隐藏验证）
#
# 职责：
#   对每个 (A, B) 组合，以 A 的 UID 身份尝试读取 B 的数据目录
#   结果写入 $RUN_DIR/verify_cache.json，供 WebUI 实时显示
#
# 【为什么用 su <uid> 而不是 su <pkg>】
#   su <uid> -c 是 KernelSU 原生支持的“切换到指定 UID 执行命令”，
#   不需要真正启动 App 进程，速度快、无副作用。
#   如果 KernelSU 配置里没开"su for all"，此命令可能失败，
#   此时我们回退到"配置级"判断（读内核 target_paths）。
#
# 用法: run_verify.sh [A包名列表]
#   A 列表可从参数传入（由 daemon_loop.sh 传递），
#   省略则从 spoof.conf 的 pkgmask_targets 读取

. "${0%/*}/lib_common.sh"

OUT="$RUN_DIR/verify_cache.json"
A_LIST="$1"
[ -z "$A_LIST" ] && A_LIST=$(get_config pkgmask_targets "")
B_LIST=$(get_config pkgmask_hide_pkgs "")

# 每个测试加超时，避免 su 切换卡死
TIMEOUT_CMD="timeout 5"

# JSON 转义
jq_s() { echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }

# 检测某 A 是否被拒绝读取 B（返回 0=已隐藏，1=可读，2=未知）
probe() {
    local a_uid="$1" b="$2"
    local target="/data/data/$b"
    local out rc

    # 尝试1：直接以 A 的 UID 执行 ls
    if [ -n "$a_uid" ]; then
        out=$($TIMEOUT_CMD su "$a_uid" -c "ls -d $target 2>&1" 2>&1)
        rc=$?
        # 成功执行（rc=0 且输出包含目录名）-> 可读
        if [ "$rc" = "0" ] && echo "$out" | grep -q "$b"; then
            echo "READABLE|$out"
            return 1
        fi
        # 明确报错 No such file / Permission denied -> 已隐藏
        case "$out" in
            *"No such file"*|*"not found"*|*"Permission denied"*|*"permission denied"*)
                echo "HIDDEN|$out"
                return 0
                ;;
        esac
    fi

    # 尝试2（兜底）：读内核 target_paths 是否包含 B 的路径
    local pm_paths
    pm_paths=$(cat "$PKG_SYSFS/target_paths" 2>/dev/null)
    case ",$pm_paths," in
        *"/data/data/$b"*|*"/data/user/0/$b"*)
            echo "CONFIGURED|内核 target_paths 已包含 $b 路径"
            return 0
            ;;
    esac

    echo "UNKNOWN|${out:-无输出}"
    return 2
}

# ---------- 主流程：对每对 (A, B) 验证 ----------
FIRST=1
{
    echo -n "["

    for a in $A_LIST; do
        [ -z "$a" ] && continue
        a_uid=$(pkg_uid "$a")
        for b in $B_LIST; do
            [ -z "$b" ] && continue

            probe "$a_uid" "$b" > "$RUN_DIR/.probe.tmp" 2>&1
            probe_result=$(cat "$RUN_DIR/.probe.tmp" 2>/dev/null)
            rm -f "$RUN_DIR/.probe.tmp"

            case "$probe_result" in
                HIDDEN\|*)       hidden=1; detail=$(echo "$probe_result" | cut -d'|' -f2-);;
                CONFIGURED\|*)   hidden=1; detail=$(echo "$probe_result" | cut -d'|' -f2-);;
                READABLE\|*)     hidden=0; detail=$(echo "$probe_result" | cut -d'|' -f2-);;
                *)               hidden=2; detail="${probe_result:-未知}";;
            esac

            [ "$FIRST" = 1 ] && FIRST=0 || echo -n ","
            printf '{"a":"%s","b":"%s","hidden":"%s","detail":"%s","a_uid":"%s"}' \
                "$(jq_s "$a")" "$(jq_s "$b")" "$hidden" \
                "$(jq_s "$detail")" "$(jq_s "$a_uid")"
        done
    done

    echo -n "]"
} > "$OUT.tmp" 2>/dev/null

# 校验 JSON 非空才替换
if [ -s "$OUT.tmp" ]; then
    mv -f "$OUT.tmp" "$OUT"
    chmod 644 "$OUT" 2>/dev/null
    log 2 "verify_hide done: $(grep -o '"a"' "$OUT" | wc -l) pairs"
else
    echo "[]" > "$OUT"
    log 1 "verify_hide: empty result"
fi

exit 0
