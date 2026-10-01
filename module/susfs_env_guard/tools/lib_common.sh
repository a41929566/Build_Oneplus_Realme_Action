#!/system/bin/sh
# SUSFS环境守护 v6.3 - 公共函数库（被各脚本 source，不单独执行）
# 兼容 mksh / ash / busybox sh，禁止使用 bash 关联数组等非 POSIX 特性

MODID="susfs_env_guard"
MODDIR="/data/adb/modules/${MODID}"
DATA_DIR="/data/adb/${MODID}"
BACKUP_DIR="${DATA_DIR}/backup"
CONF="${DATA_DIR}/spoof.conf"
PROFILE="${DATA_DIR}/fake_profile.conf"
RUN_DIR="${MODDIR}/run"
ACTION_FILE="${DATA_DIR}/action.txt"
PKG_SYSFS="/sys/module/pkgmask/parameters"
# hwid_spoof is built into pkgmask by this repository. Only select a
# standalone directory when it exposes the complete control surface.
HWID_SYSFS="$PKG_SYSFS"
SUSFS_JSON="/data/adb/ksu/.susfs.json"
if [ -f "/sys/module/hwid_spoof/parameters/hwid_enabled" ] &&
   [ -f "/sys/module/hwid_spoof/parameters/hwid_reload" ]; then
    HWID_SYSFS="/sys/module/hwid_spoof/parameters"
fi

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$DATA_DIR/logs" "$RUN_DIR" 2>/dev/null
[ -f "$CONF" ] || [ ! -f "$MODDIR/config/spoof.conf.example" ] ||
    cp -f "$MODDIR/config/spoof.conf.example" "$CONF" 2>/dev/null

bool_on() {
    case "$1" in
        1|Y|y|true|TRUE|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- 日志 ----------
_log_level() {
    local lv
    lv=$(grep '^log_level=' "$CONF" 2>/dev/null | cut -d= -f2)
    [ -z "$lv" ] && lv=3
    echo "$lv"
}
log() {
    local level=$1; shift
    local msg="$*"
    local cur; cur=$(_log_level)
    local prefix
    case "$level" in
        0) prefix="ERROR" ;; 1) prefix="WARN" ;; 2) prefix="INFO" ;;
        3) prefix="DEBUG" ;; *) prefix="TRACE" ;;
    esac
    [ "$level" -le "$cur" ] 2>/dev/null && \
        echo "[$(date +%m-%d\ %H:%M:%S)][$prefix] $msg" >> "$RUN_DIR/guard.log"
}

# ---------- 配置 ----------
# get_config <key> [default]
get_config() {
    local key=$1 def=$2 v
    v=$(grep "^${key}=" "$CONF" 2>/dev/null | head -1 | cut -d= -f2-)
    v=$(echo "$v" | sed 's/^"//; s/"$//')
    [ -z "$v" ] && v="$def"
    echo "$v"
}
# set_config <key> <value>  （不存在则追加）
set_config() {
    local key=$1 val=$2
    # 不用 sed + 分隔符替换（值里可能含 | / /，会被转义搅坏）。
    # 直接删旧行后追加新行，值原样写入，不经过任何转义解释。
    grep -v "^${key}=" "$CONF" > "$CONF.cfgtmp" 2>/dev/null
    echo "${key}=${val}" >> "$CONF.cfgtmp" 2>/dev/null
    mv -f "$CONF.cfgtmp" "$CONF" 2>/dev/null
}

# cfg_add <key> <item>  —— 空格分隔列表里去重追加一项
cfg_add() {
    local key=$1 item=$2 cur
    [ -z "$item" ] && return
    cur=$(get_config "$key" "")
    case " $cur " in *" $item "*) return 0 ;; esac
    set_config "$key" "${cur:+$cur }$item"
}

# cfg_del <key> <item>  —— 从空格分隔列表里删一项
cfg_del() {
    local key=$1 item=$2 cur new
    [ -z "$item" ] && return
    cur=$(get_config "$key" "")
    new=$(echo "$cur" | tr ' ' '\n' | grep -vxF "$item" | tr '\n' ' ' | sed 's/  */ /g;s/^ //;s/ $//')
    set_config "$key" "$new"
}

init_feature_flags() {
    local base
    if ! grep -q '^feature_flags_initialized=' "$CONF" 2>/dev/null; then
        # Legacy global enable must not silently turn on every new feature.
        # New installs and migrated installs both start in explicit opt-in mode.
        base=0
        grep -q '^spoof_props_enabled=' "$CONF" 2>/dev/null ||
            echo "spoof_props_enabled=$base" >> "$CONF"
        grep -q '^spoof_hwid_enabled=' "$CONF" 2>/dev/null ||
            echo "spoof_hwid_enabled=$base" >> "$CONF"
        grep -q '^spoof_android_id=' "$CONF" 2>/dev/null ||
            echo "spoof_android_id=$base" >> "$CONF"
        echo "feature_flags_initialized=1" >> "$CONF"
    fi
}

# ---------- 工具定位 ----------
RESETPROP=""
MAGISKPOLICY=""
_locate_tools() {
    # === 修复3：分层级稳健检测，确保在 post-fs-data 阶段即使 KSU bind_mount 未就绪也能工作 ===
    # L0: 先检测 KSU/AP 路径（它们在 post-fs-data 后期才 bind_mount，早期可能不可用）
    #      额外增加可用性验证（执行轻量 --help 探测），避免拿到空壳路径
    for c in /data/adb/ksu/bin/resetprop /data/adb/ap/bin/resetprop; do
        if [ -x "$c" ]; then
            if "$c" -h >/dev/null 2>&1 || "$c" --help >/dev/null 2>&1 || "$c" >/dev/null 2>&1; then
                RESETPROP="$c"
                break
            fi
        fi
    done
    # L1: Magisk 路径（其 bind_mount 通常更早就绪）
    if [ -z "$RESETPROP" ]; then
        for c in /data/adb/magisk/resetprop /debug_ramdisk/.magisk/resetprop; do
            if [ -x "$c" ]; then
                RESETPROP="$c"
                break
            fi
        done
    fi
    # L2: PATH 查找（最后的回退）
    if [ -z "$RESETPROP" ]; then
        if command -v resetprop >/dev/null 2>&1; then
            RESETPROP="resetprop"
        fi
    fi
    # L3: 硬兜底
    [ -z "$RESETPROP" ] && RESETPROP="resetprop"

    # magiskpolicy：同理分层
    for c in /data/adb/ksu/bin/magiskpolicy /data/adb/ap/bin/magiskpolicy; do
        if [ -x "$c" ]; then
            MAGISKPOLICY="$c"
            break
        fi
    done
    if [ -z "$MAGISKPOLICY" ]; then
        for c in /data/adb/magisk/magiskpolicy magiskpolicy; do
            if [ -x /data/adb/magisk/magiskpolicy ]; then
                MAGISKPOLICY="/data/adb/magisk/magiskpolicy"
                break
            fi
            if command -v magiskpolicy >/dev/null 2>&1; then
                MAGISKPOLICY="magiskpolicy"
                break
            fi
        done
    fi
    [ -z "$MAGISKPOLICY" ] && MAGISKPOLICY="magiskpolicy"
}
_locate_tools

# rp_set <prop> <val>  ：设置属性（-n 不同步到默认值区，避免被还原时残留）
rp_set() { "$RESETPROP" -n "$1" "$2" 2>/dev/null || "$RESETPROP" "$1" "$2" 2>/dev/null; }
# rp_del <prop> ：删除我们覆盖的属性，恢复内核/init 原始值
rp_del() { "$RESETPROP" --delete "$1" 2>/dev/null; "$RESETPROP" -d "$1" 2>/dev/null; }

# ---------- 备份原语（只备份一次，绝不覆盖原始真值） ----------
# backup_once <文件名> <原始值>
backup_once() {
    local f="$BACKUP_DIR/$1" v="$2"
    [ -f "$f" ] && return 0
    echo "$v" > "$f"
}
backup_read() { cat "$BACKUP_DIR/$1" 2>/dev/null; }

# ---------- 随机生成（有限读取，绝不阻塞） ----------
rand_hex() { head -c "${1:-8}" /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n'; }
# 8 位大写字母数字（一加真机序列号形态）。A-Z0-9 在随机字节中占比约 14%，
# 故需读取足够多原始字节再过滤，避免不足 8 位（不足会被检测为异常）。
rand_serial8() {
    # 一加真机 ro.serialno 是 8 位小写 hex（如 261418ea）
    # 旧版生成 A-Z0-9 大写字母数字，含 G-Z 非 hex 字符，格式不符
    local s
    s=$(rand_hex 4)
    # 兜底：确保恰好 8 位
    while [ ${#s} -lt 8 ]; do s="${s}0"; done
        echo "$s" | cut -c1-8
}
# 一加 incremental 形态：纯数字（如 U.PR/日期+序号），这里生成 7-10 位数字
rand_incremental() {
    local y m d n
    y=$(date +%Y); m=$(date +%m); d=$(date +%d)
    n=$(head -c 4 /dev/urandom 2>/dev/null | od -An -tu4 2>/dev/null | tr -dc '0-9' | head -c 6)
    echo "${y}${m}${d}${n}" | head -c 14
}
# 合法本地管理 MAC
rand_mac() {
    local h; h=$(head -c 6 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    # 强制第一字节本地管理位=1、单播位=0 -> 02/06/0a/0e
    local b0; b0=$(printf '%02x' $(( (0x$(echo "$h" | cut -c1-2) & 0xfc) | 0x02 )))
    echo "$b0:$(echo "$h" | cut -c3-4):$(echo "$h" | cut -c5-6):$(echo "$h" | cut -c7-8):$(echo "$h" | cut -c9-10):$(echo "$h" | cut -c11-12)"
}

# ---------- 包名 -> UID（多通道，避免 shell exec 卡死） ----------
# 优先 dumpsys/stat，兜底 pm list；输出第一个 uid
pkg_uid() {
    local pkg=$1 uid=""
    # 通道1: /data/data 目录属主（最快，不依赖 pm）
    for d in /data/data/$pkg /data/user/0/$pkg; do
        if [ -d "$d" ]; then
            uid=$(stat -c %u "$d" 2>/dev/null)
            [ -n "$uid" ] && { echo "$uid"; return; }
        fi
    done
    # 通道2: 全量列出后按包名边界精确匹配（避免 -U filter 子串误匹配同名前缀包）
    uid=$(timeout 5 pm list packages -U 2>/dev/null \
        | grep -E "^package:${pkg}( |$)" | grep -o 'uid:[0-9]*' \
        | head -1 | cut -d: -f2)
    echo "$uid"
}

# ---------- 状态上报共用原语（daemon_loop.sh / status_now.sh 共用，避免两份实现漂移） ----------
USER_PATHS_FILE="${DATA_DIR}/user_hidden_paths.txt"

gprop() { getprop "$1" 2>/dev/null; }
catf() { cat "$1" 2>/dev/null; }
# JSON 字符串转义：去掉真实换行（单行字段用）
# 必须用 printf 而不是 echo：echo 在 dash/ash 等 shell 下会解释反斜杠转义，
# 把值里的 "\1" 变成 0x01 控制字符 —— 控制字符在 JSON 字符串里非法。
jq_s() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }
# 保留内容原样、只转义反斜杠与引号（多行字段用；换行以字面 \n 两字符写入，前端按 "\\n" 切分）
jq_s_raw() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

list_user_paths() {
    [ -f "$USER_PATHS_FILE" ] || return 0
    grep -v '^[[:space:]]*#' "$USER_PATHS_FILE" 2>/dev/null | grep -v '^[[:space:]]*$'
}

# SUSFS 生效面检测：输出以字面 \n 分隔的记录，每条 5 字段 "名称|状态|当前|期望|原因"
detect_susfs() {
    local out=""
    local bc_kernel; bc_kernel=$(catf /proc/bootconfig | tr '\n' ' ')
    local cl_kernel; cl_kernel=$(catf /proc/cmdline | tr '\n' ' ')
    local bc_ok=0
    case "$bc_kernel" in *verifiedbootstate*green*) bc_ok=$((bc_ok+1));; esac
    case "$bc_kernel" in *vbmeta.device_state*locked*) bc_ok=$((bc_ok+1));; esac
    if [ "$bc_ok" -ge 2 ]; then
        out="${out}bootconfig伪装|ok|green/locked|green/locked|/proc/bootconfig 已重定向\n"
    else
        out="${out}bootconfig伪装|fail|${bc_kernel:-空}|green/locked|SUSFS cmdline_or_bootconfig 未生效\n"
    fi
    if grep -q '"/proc/cmdline"' "$SUSFS_JSON" 2>/dev/null; then
        out="${out}cmdline重定向|ok|已配置|green|/proc/cmdline 已重定向\n"
    else
        out="${out}cmdline重定向|warn|未配置|green|open_redirect 未写入\n"
    fi
    local p1 p2 p3
    p1=$(gprop ro.boot.verifiedbootstate)
    p2=$(gprop ro.boot.vbmeta.device_state)
    p3=$(gprop ro.boot.flash.locked)
    local cur_vals="${p1:-空}/${p2:-空}/${p3:-空}"
    if [ "$p1" = "green" ] && [ "$p2" = "locked" ] && [ "$p3" = "1" ]; then
        out="${out}prop三连|ok|$cur_vals|green/locked/1|属性层已伪装\n"
    elif [ "$bc_ok" -ge 2 ]; then
        out="${out}prop三连|ok|$cur_vals + 内核重定向|green/locked/1|应用读取走内核\n"
    else
        out="${out}prop三连|warn|$cur_vals|green/locked/1|请点一键修复\n"
    fi
    if grep -q '"avc_log_spoofing": true' "$SUSFS_JSON" 2>/dev/null; then
        out="${out}AVC日志伪装|ok|已启用|已启用|免疫 AVC 审计\n"
    else
        out="${out}AVC日志伪装|warn|未启用|已启用|内核可能不支持\n"
    fi
    if grep -q '"hide_sus_mnts_for_non_su_procs": true' "$SUSFS_JSON" 2>/dev/null; then
        out="${out}挂载隐藏|ok|已启用|已启用|非root看不到 sus 挂载\n"
    else
        out="${out}挂载隐藏|warn|未启用|已启用|内核可能不支持\n"
    fi
    local path_count
    path_count=$(catf "$SUSFS_JSON" | grep -c '"path"' 2>/dev/null)
    path_count=${path_count:-0}
    if [ "$path_count" -gt 0 ]; then
        out="${out}路径循环隐藏|ok|$path_count 条|>0|已注册\n"
    else
        out="${out}路径循环隐藏|warn|0 条|>0|未注册\n"
    fi
    local KS
    KS=$(command -v ksu_susfs 2>/dev/null || \
         for p in /data/adb/ksu/bin/ksu_susfs /data/adb/ksud/bin/ksu_susfs; do
             [ -x "$p" ] && { echo "$p"; break; }
         done)
    if [ -n "$KS" ]; then
        out="${out}ksu_susfs工具|ok|$KS|存在|就绪\n"
    else
        out="${out}ksu_susfs工具|fail|未找到|存在|内核未编译 SUSFS\n"
    fi
    printf '%s' "$out"
}
#（注：内容由AI生成）
