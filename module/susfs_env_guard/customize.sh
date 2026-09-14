#!/system/bin/sh
# SUSFS环境守护 v6.2 - customize.sh（标准 KSU/ReSukiSU/Magisk/APatch 模块安装）
SKIPUNZIP=1
MODID="susfs_env_guard"

ui_print "=========================================="
ui_print "  SUSFS环境守护 v6.2"
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

# 3) 数据/基础目录（刷机后自动生成，全部幂等）
ui_print "- 生成基础目录与配置..."
D=/data/adb/$MODID
mkdir -p "$D/backup" "$D/logs" /data/adb/pkgmask
[ -f "$D/spoof.conf" ] || cp -f "$MODPATH/config/spoof.conf.example" "$D/spoof.conf"

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

# 6) 升级保留用户数据（不覆盖 fake_profile / backup / spoof.conf）
ui_print "- 保留已有伪装档案与备份"

ui_print "=========================================="
ui_print "  安装完成，重启后生效"
ui_print "  硬件只读ID需包含 hwid_spoof 的内核"
ui_print "=========================================="