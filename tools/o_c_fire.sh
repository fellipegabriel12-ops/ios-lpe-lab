#!/bin/sh
# o_c_fire.sh - decode every staged payload and watch for kernel panic
cd "$(dirname "$0")"/.o_c/channel || exit 1
for f in oc_*.h264 trigger*.pdf trigger*.ttf; do
  [ -f "$f" ] || continue
  echo "[$(date +%H:%M:%S)] firing $f"
  # CGPOC decodes the file; if the kernel panics, the device reboots
  # and we read the panic log. If it returns, the payload was rejected.
  timeout 10 /var/containers/Bundle/Application/*/CGPOC.app/CGPOC "$f" 2>&1 | head -5
  echo "  -> returned (no panic)"
done
echo "all payloads fired; checking for panic logs"