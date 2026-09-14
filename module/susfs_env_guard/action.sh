#!/system/bin/sh
# 管理器“执行”入口：重新应用全部规则并打印自检
MODDIR=${0%/*}
. "$MODDIR/tools/lib_common.sh"
echo "================ SUSFS环境守护 v6.3 ================"
sh "$MODDIR/tools/props_spoof.sh" apply
sh "$MODDIR/tools/randomize.sh" apply
sh "$MODDIR/tools/pkgmask_setup.sh" apply
sh "$MODDIR/tools/appops_setup.sh" apply
echo "---------------- 自检 ----------------"
sh "$MODDIR/tools/selfcheck.sh"
echo "----------------------------------------------------"
echo "WebUI 可查看实时状态；动作已写入 action.txt 由守护消费"
