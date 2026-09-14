#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/Build_oneplus_sm8750_pkgmask.yml"
pkgmask="patch/patch/pkgmask/pkgmask.c"

python3 - "$workflow" "$pkgmask" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1])
pkgmask = Path(sys.argv[2])

w = workflow.read_text()

old = """            oneplus_13 | oneplus_13t | oneplus_ace5_pro | oneplus_ace_6 | oneplus_pad_2 | realme_GT7 | realme_GT7pro_Speed | realme_GT8)
                DEFAULT_SUFFIX='-android15-8-g93e223c276e7-abogki500782043-4k'
"""
new = """            oneplus_ace5_pro)
                DEFAULT_SUFFIX='-android15-8-g7e1f3c083cc6-abogki467167594-4k'
              ;;
            oneplus_13 | oneplus_13t | oneplus_ace_6 | oneplus_pad_2 | realme_GT7 | realme_GT7pro_Speed | realme_GT8)
                DEFAULT_SUFFIX='-android15-8-g93e223c276e7-abogki500782043-4k'
"""
if w.count(old) != 1:
    raise SystemExit("workflow suffix block not found exactly once")
w = w.replace(old, new, 1)

old = """              oneplus_13 | oneplus_13t | oneplus_ace5_pro | oneplus_ace_6 | oneplus_pad_2 |realme_GT7 | realme_GT7pro_Speed | realme_GT8)
                  KERNEL_TIME='Wed Apr  8 15:08:30 UTC 2026'
"""
new = """              oneplus_ace5_pro)
                  KERNEL_TIME='Mon Dec  8 04:00:43 UTC 2025'
                ;;
              oneplus_13 | oneplus_13t | oneplus_ace_6 | oneplus_pad_2 |realme_GT7 | realme_GT7pro_Speed | realme_GT8)
                  KERNEL_TIME='Wed Apr  8 15:08:30 UTC 2026'
"""
if w.count(old) != 1:
    raise SystemExit("workflow timestamp block not found exactly once")
w = w.replace(old, new, 1)

old = """          sudo sed -i 's/^SUBLEVEL = 118/SUBLEVEL = 89/' ./common/Makefile
          sudo sed -i 's/^filechk_utsrelease = .*/filechk_utsrelease = 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k/' ./common/Makefile || true
          grep -n '^SUBLEVEL\\|^filechk_utsrelease' ./common/Makefile || true
          echo CONFIG_LOCALVERSION="-android15-8-g7e1f3c083cc6-abogki467167594-4k" >> ./common/arch/arm64/configs/gki_defconfig
          echo "[OK] Kernel version spoofed to 6.6.89 with consistent localversion"
"""
new = """          if [ "${{ env.DEVICES_NAME }}" = "oneplus_ace5_pro" ]; then
            sudo sed -i 's/^SUBLEVEL = 118/SUBLEVEL = 89/' ./common/Makefile
          sudo sed -i 's/^filechk_utsrelease = .*/filechk_utsrelease = 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k/' ./common/Makefile
          grep -q '^SUBLEVEL = 89$' ./common/Makefile || { echo "FATAL: 无法设置内核 SUBLEVEL=89"; exit 1; }
          echo CONFIG_LOCALVERSION="-android15-8-g7e1f3c083cc6-abogki467167594-4k" >> ./common/arch/arm64/configs/gki_defconfig
          echo "[OK] 使用设备目标内核版本 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
          fi
"""
if w.count(old) != 1:
    raise SystemExit("workflow version spoof block not found exactly once")
w = w.replace(old, new, 1)

anchor = """          echo "ccache 状态："
          ccache -s
"""
verify = """          echo "ccache 状态："
          ccache -s
      - name: 🔎 Verify final kernel features and release (验证最终内核配置与功能)
        run: |
          if [ "${{ env.DEVICES_NAME }}" != "oneplus_ace5_pro" ]; then
            echo "非 oneplus_ace5_pro，跳过 Ace 5 Pro 专用 kernel.release 校验"
            exit 0
          fi
          cd kernel_workspace/common
          test -f out/.config || { echo "FATAL: out/.config 缺失"; exit 1; }
          grep -Eq '^CONFIG_PKGMASK=y$' out/.config || { echo "FATAL: CONFIG_PKGMASK 未生效"; exit 1; }
          grep -Eq '^CONFIG_KPROBES=y$' out/.config || { echo "FATAL: CONFIG_KPROBES 未生效"; exit 1; }
          grep -Eq '^CONFIG_KRETPROBES=y$' out/.config || { echo "FATAL: CONFIG_KRETPROBES 未生效"; exit 1; }
          test -f out/vmlinux || { echo "FATAL: out/vmlinux 缺失"; exit 1; }
          LLVM_NM=../clang18/bin/llvm-nm
          [ -x "$LLVM_NM" ] || LLVM_NM=llvm-nm
          "$LLVM_NM" out/vmlinux | grep -Eq '(^| )hwid_spoof_init$' || { echo "FATAL: hwid_spoof_init 未链接进 vmlinux"; exit 1; }
          RELEASE=$(cat out/include/config/kernel.release 2>/dev/null || true)
          echo "最终 kernel.release=$RELEASE"
          test "$RELEASE" = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k" || {
            echo "FATAL: 最终 kernel.release 不匹配设备：$RELEASE"
            exit 1
          }
"""
if w.count(anchor) != 1:
    raise SystemExit("workflow build anchor not found exactly once")
w = w.replace(anchor, verify, 1)

p = pkgmask.read_text()
old = """\t\thide_proc_enabled ? 1 : 0, proc_name_count);
"""
new = """\t\tenable_syscall_hooks ? 1 : 0, binder_enabled ? 1 : 0,
\t\thide_proc_enabled ? 1 : 0, proc_name_count);
"""
if p.count(old) != 1:
    raise SystemExit("pkgmask log argument block not found exactly once")
workflow.write_text(w)
pkgmask.write_text(p.replace(old, new, 1))
PY

echo "Applied workflow and pkgmask fixes."
