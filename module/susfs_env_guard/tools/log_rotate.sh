#!/system/bin/sh
# 日志轮转：单个日志超过阈值则截断保留尾部，避免无限增长（POSIX）
. "${0%/*}/lib_common.sh"
MAX_KB=$(get_config log_max_kb 512)
for f in "$RUN_DIR"/*.log "$DATA_DIR/logs"/*.log; do
    [ -f "$f" ] || continue
    kb=$(($(stat -c %s "$f" 2>/dev/null || echo 0) / 1024))
    if [ "$kb" -gt "$MAX_KB" ]; then
        tail -n 200 "$f" > "$f.t" 2>/dev/null && mv -f "$f.t" "$f"
    fi
done
exit 0
