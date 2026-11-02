#!/bin/sh
# O-C (session "jailbreak 3") - ONE-LINE RUNNER for the iPhone (a-Shell).
#
#   curl -s http://192.168.12.39:8765/get/run_probe.sh -o /var/mobile/Media/Downloads/run_probe.sh; sh /var/mobile/Media/Downloads/run_probe.sh
#
# It:
#   1. measures the ENCODER side ceiling (vtprobe.py, already on the phone)
#   2. measures the DECODER side ceiling and drives a frame (oc_vtdec_ceiling.py)
#   3. pushes every result file back to the rig so we get exact numbers
RIG=192.168.12.39
D=/var/mobile/Media/Downloads
mkdir -p $D 2>/dev/null
cd $D 2>/dev/null || cd ~/Documents
D=$(pwd)
echo "=== OC START $(date) in $D ==="

get() { [ -f "$2" ] || curl -s --max-time 40 "http://$RIG:8765/get/$1" -o "$2"; }
get vtprobe.py vtprobe.py
get oc_vt_ceiling.py oc_vt_ceiling.py
get oc_vtdec_ceiling.py oc_vtdec_ceiling.py
get run_all.sh run_all.sh
ls -la vtprobe.py oc_vt_ceiling.py oc_vtdec_ceiling.py 2>&1

echo "--- 1) encoder ceiling (vtprobe) ---"
python3 vtprobe.py 2>&1 | tail -30

echo "--- 2) encoder ceiling + DPBMode variants (oc_vt_ceiling) ---"
python3 oc_vt_ceiling.py 2>&1 | tail -70

echo "--- 3) DECODER ceiling + frame submit (oc_vtdec_ceiling) ---"
python3 oc_vtdec_ceiling.py 2>&1 | tail -80

echo "--- pushing results to the rig ---"
for f in vtprobe_out.txt oc_vt_ceiling_out.txt oc_vtdec_out.txt; do
  if [ -f "$D/$f" ]; then
    echo "--- $f ---"
    cat "$D/$f"
    curl -s --max-time 30 -X POST --data-binary "@$D/$f" "http://$RIG:8765/put/$f" >/dev/null && echo "[pushed $f]"
  fi
done
echo "=== OC END $(date) ==="
