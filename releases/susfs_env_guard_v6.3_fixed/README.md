# SUSFS-Env-Guard v6.3 稳定版（能开机配置）

## 为什么改
原始模块在 post-fs-data 阶段修改 `ro.build.fingerprint`、
`ro.serialno` 等启动完整性属性，导致系统循环重启。

## 改了什么
1. `spoof_serial=0`、`spoof_build=0`
   → 不再改 fingerprint / serialno / incremental
2. `post-fs-data.sh` 里注释掉 `randomize.sh apply`
   → hwid_spoof 延后到 service.sh 启用，避免 zygote 前挂 vfs_read hook

## 如何刷入
1. 先刷 AK3 内核
2. 进 Recovery 清掉旧配置：
   rm -rf /data/adb/modules/susfs_env_guard
   rm -rf /data/adb/susfs_env_guard
3. 进系统，ReSukiSU 管理器刷入 SUSFS-Env-Guard-fixed2.zip
4. 刷完先别重启，检查配置：
   grep -E '^(spoof_serial|spoof_build)=' /data/adb/susfs_env_guard/spoof.conf
   必须看到 spoof_serial=0 和 spoof_build=0
5. 重启，应该能正常进系统

## 版本
- 内核：6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k
- 模块：SUSFS-Env-Guard v6.3
