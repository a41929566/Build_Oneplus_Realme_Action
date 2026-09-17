#!/system/bin/sh
# 资源占用只读检查
. "${0%/*}/lib_common.sh"
echo "=== 守护进程 ==="
ps -A 2>/dev/null | grep -E "daemon_loop" | grep -v grep
echo "=== /data 占用 ==="
df -h /data 2>/dev/null | tail -1
du -sh "$DATA_DIR" 2>/dev/null
echo "=== 本模块日志大小 ==="
ls -lh "$RUN_DIR"/*.log 2>/dev/null
echo "=== 内存 ==="
for p in $(pidof daemon_loop.sh 2>/dev/null); do
    grep -E "Name|VmRSS" /proc/$p/status 2>/dev/null | tr '\n' ' '; echo " (pid $p)"
done
