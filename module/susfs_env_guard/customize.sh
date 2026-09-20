#!/system/bin/sh
# SUSFS环境守护 v6.3 - customize.sh（标准 KSU/ReSukiSU/Magisk/APatch 模块安装）
SKIPUNZIP=1
MODID="susfs_env_guard"

ui_print "=========================================="
ui_print "  SUSFS环境守护 v6.3"
ui_print "  属性全通道一致 + 内核硬件ID + pkgmask"
ui_print "=========================================="

[ "$BOOTMODE" = "true" ] || abort "! 请在管理器中刷入，勿在 Recovery 刷入"
ui_print "- 安装目录: $MODPATH"

# 1) 解压自身全部文件
ui_print "- 释放模块文件..."
unzip -o "$ZIPFILE" -d "$MODPATH" >/dev/null 2>&1 || abort "! 解压失败"
[ -f "$MODPATH/module.prop" ] || abort "! module.prop 缺失"

# 2) 权限
set_perm_recursive "$MODPATH" 0 0 0755 0644
chmod 755 "$MODPATH"/*.sh 2>/dev/null
chmod 755 "$MODPATH/tools/"*.sh 2>/dev/null
[ -f "$MODPATH/META-INF/com/google/android/update-binary" ] && \
    chmod 755 "$MODPATH/META-INF/com/google/android/update-binary"

# 2b) NeoZygisk 文件权限
ui_print "- 设置 NeoZygisk 运行时文件权限..."
mkdir -p "$MODPATH/bin" "$MODPATH/lib64"
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/lib64" 0 0 0755 0644 u:object_r:system_lib_file:s0

# 3) 数据/基础目录（刷机后自动生成，全部幂等）
ui_print "- 生成基础目录与配置..."
D=/data/adb/$MODID
mkdir -p "$D/backup" "$D/logs" /data/adb/pkgmask

# 强制覆盖 spoof.conf，确保本次刷入的安全配置生效
# （旧版本用 [ -f ] || 判断，旧配置不会被覆盖，导致改了 spoof.conf.example 也无效）
cp -f "$MODPATH/config/spoof.conf.example" "$D/spoof.conf"
ui_print "- spoof.conf 已强制覆盖为最新安全配置"

# 4) 备份旧的 fake_profile（如果存在），避免假值残留造成不一致
if [ -f "$D/fake_profile.conf" ]; then
    cp -f "$D/fake_profile.conf" "$D/fake_profile.conf.bak.$(date +%s)" 2>/dev/null
    ui_print "- 旧 fake_profile.conf 已备份"
fi

# 5) 内核能力提示；具体功能仍由 selfcheck 在启动后确认
if [ -d /sys/module/pkgmask/parameters ]; then
    ui_print "- pkgmask: detected"
else
    ui_print "! pkgmask: missing (package masking unavailable)"
fi
if [ -f /sys/module/pkgmask/parameters/hwid_enabled ]; then
    ui_print "- hwid_spoof: detected"
else
    ui_print "! hwid_spoof: missing (read-only ID interception unavailable)"
fi

ui_print "=========================================="
ui_print "  安装完成，重启后生效"
ui_print "  硬件只读ID需包含 hwid_spoof 的内核"
ui_print "=========================================="
