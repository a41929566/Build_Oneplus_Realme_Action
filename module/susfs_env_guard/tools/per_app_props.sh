#!/system/bin/sh
# per_app_props.sh - Per-App 属性配置管理
# 注意：临时路径名来自插件硬编码，与 ReZygisk 已废弃无关
# 用法: per_app_props.sh [getFeatures|setFeatures|setTargetPackage|getStatus]

PAP_TMP_FEATURES=/.per_app_props_features
PAP_TMP_TARGET=/.per-app-props/target_package.conf
PAP_PERSIST_DIR=/data/adb/susfs_env_guard/per_app_props
PAP_PERSIST_FEATURES=$PAP_PERSIST_DIR/features.conf
PAP_PERSIST_TARGET=$PAP_PERSIST_DIR/target_package.conf

mkdir -p "$PAP_PERSIST_DIR" 2>/dev/null

case "$1" in
    getFeatures)
        if [ -f "$PAP_TMP_FEATURES" ]; then
            cat "$PAP_TMP_FEATURES"
        else
            echo "version=1"
            echo "cpu=1"
            echo "gpu=1"
            echo "cpuinfo=1"
            echo "gpu_driver=mali"
        fi
        ;;
    setFeatures)
        cat > "$PAP_PERSIST_FEATURES"
        cp "$PAP_PERSIST_FEATURES" "$PAP_TMP_FEATURES" 2>/dev/null
        echo "OK"
        ;;
    setTargetPackage)
        [ -z "$2" ] && { echo "Usage: $0 setTargetPackage <package_name>"; exit 1; }
        echo -n "$2" > "$PAP_PERSIST_TARGET"
        cp "$PAP_PERSIST_TARGET" "$PAP_TMP_TARGET" 2>/dev/null
        echo "target_package=$2"
        ;;
    getStatus)
        echo "state=active"
        echo "backend=zygisk"
        echo "target_abi=arm64-v8a"
        echo "scope=process-local"
        if [ -f "$PAP_TMP_TARGET" ]; then
            echo "target_package=$(cat $PAP_TMP_TARGET)"
        else
            echo "target_package="
        fi
        ;;
    *)
        echo "Usage: $0 [getFeatures|setFeatures|setTargetPackage|getStatus]"
        exit 1
        ;;
esac
