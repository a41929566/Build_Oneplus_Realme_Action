#!/system/bin/sh
# SUSFS环境守护 v6.2 - 公共函数库（被各脚本 source，不单独执行）
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
HWID_SYSFS="/sys/module/hwid_spoof/parameters"
[ -d "$HWID_SYSFS" ] || HWID_SYSFS="$PKG_SYSFS"

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$DATA_DIR/logs" "$RUN_DIR" 2>/dev/null

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
    if grep -q "^${key}=" "$CONF" 2>/dev/null; then
        # 用 | 作分隔避免值里的 / 冲突；值里不允许出现 |
        sed -i "s|^${key}=.*|${key}=${val}|" "$CONF" 2>/dev/null
    else
        echo "${key}=${val}" >> "$CONF"
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
    local s
    s=$(head -c 256 /dev/urandom 2>/dev/null | tr -dc 'A-Z0-9' 2>/dev/null | head -c 8)
    if [ ${#s} -lt 8 ]; then
        # 极端兜底：用 hex 映射，保证一定有 8 位
        s=$(rand_hex 4 | tr 'a-f' 'A-F')
    fi
    echo "$s"
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