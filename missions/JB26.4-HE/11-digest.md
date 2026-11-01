# 11-digest.md — the one-pager for He (Magna VIII.6: HE-DIGEST per-pass)

Pass date: 2026-11-01 · mission JB26.4-HE · authors: O-D (+ siblings)

**what happened this pass —**
1. **The file-read primitive is live ON 26.4** (CVE-2026-112706 via mediaplaybackd CoreMedia XPC). Verified on our exact device, Tier-0, twice. First stolen file: GlobalPreferences.plist 2,821 B, bplist-header verified in the workspace (.o_c/mconf_results).
2. **CVE-2026-84607 confirmed OPEN on our build.** The census reads the "EncType mismatch" strings: 0 in 23E246, 2 in 27.0.1 → the race door is open, classified T-0.
3. **The whole AppleAVE2 gate map is now written:** the client session cap is DEAD (descriptor lie, all money sizes), two kext-side walls named (-8971 record-vs-descriptor, -12909 frame-vs-config) — the multiply sits behind one of them, so the trigger path = either a bypass of TWO walls or a different door.
4. **A second kext shelf opened**: AppleAVD (HEVC) = 5 live CVEs on our build, reachable from plain VideoToolbox, and our own harness for it is built and waiting-roomed. If CI minutes come back, it's one shot away.
5. **Infrastructure hardened along the way**: the automated install lane (no 2FA races), patched the sibling's census tool (missing import — the multiply census now actually runs), xnu-12377.1.9 source pulled for the offsets contract (exact field anchors, no guesses), the offsets resolver machinery (BaseBin XPF/ChOma) cloned for the 23E246 kernelcache on disk.

**what changed class-wise —** the operation's sandbox lane is no longer empty: we have a working, on-device, unsigned-app file-read primitive with the dir-list + fd-steal modes armed (one more tap on the phone = the entire /usr/libexec ground-truth shelf).

**planned next (by ROI-rank, per 01-plan) —** ① the /usr/libexec dir-list pull, ② the HEVC probe fires when minutes return, ③ the multiplies census Q3 finishes offline, ④ the 84607 race harness design hands to the sibling, ⑤ the offsets resolver runs against the 23E246 kcache.

**the change-log curtosy rule (L-011) —** zero violations logged this pass; the device never saw a flashing op; every artifact went through the board with tier-tags.
