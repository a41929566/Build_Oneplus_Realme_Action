#!/system/bin/sh
# SUSFS Env Guard v3.0 - 管理器"执行"入口
#
# 作用：
#   1) 管理器（KernelSU / ReSukiSU 等）里点模块的"执行"按钮时触发
#   2) 统一调用 run.sh，按序执行所有伪装逻辑
#   3) 打印自检结果，方便终端直接查看
#
# 注：run.sh 内部已包含等待 boot_completed 和 settings 服务的逻辑，
#     手动执行时如果系统已就绪，会立即执行（等待循环只跑 1 次）

. "${0%/*}/tools/lib_common.sh"

echo "================ SUSFS Env Guard v3.0 ================"
echo "触发方式：管理器执行按钮"
echo ""

# 1) 统一执行所有伪装逻辑
sh "$MODDIR/tools/run.sh"

echo ""
echo "---------------- 自检 ----------------"
# 2) 打印自检结果
sh "$MODDIR/tools/selfcheck.sh"

echo "----------------------------------------------------"
# 原注释声称「守护进程每 15 秒聚合一次 status.json」，与实际实现不符：
#   ① 常驻 daemon 从未被启动（run.sh 不常驻，WebUI 只跑 daemon_loop.sh --once）；
#   ② write_status() 写出的 webroot/status.json 全仓无任何读取方；
#   ③ WebUI 的实时状态来自 webroot/index.html 每 2.5s 调用 tools/status_now.sh。
# 这里按实际情况描述，避免误导排查者。
echo "WebUI 实时状态：index.html 每 2.5s 调用 tools/status_now.sh 直读 sysfs"
exit 0
