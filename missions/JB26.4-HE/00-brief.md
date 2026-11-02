# JB26.4-HE — 00-brief (mission casefile · Magna v9.2 · L-241)

- Row-id: JB26.4-HE.00
- session: O-D (this side). cof: the "jailbreak 3"-line siblings (O-A CI / O-B device / nj2 kext / O-C provisioning) on the shared run + board (github.com/fellipegabriel12-ops/ios-lpe-lab).
- He's target: **iPhone17,3 — iPhone 16 Pro — A18 Pro (t8140) — iOS 26.4 (23E246)** — serial CK0773N6TM, ours (chosen by He; ROI-owned by He's mission ask).
- Objective: userland jailbreak on 26.4 (ElleKit/Procursus-class result), u0 covered by the sibling chain (86950→64740/28995→64747/84607→physrw→uid 0).
- Danger class / kill-switches inherited:
  - K1: no flashing device-touch ops (ODA = "operate-the-decode-artifact" only). Shell the device never flashes; a panic = a reboot, not a brick.
  - K2: All A-file artifacts go through the board with tier-tags (T-0 measured, T-1 source, T-3 reasoned, T-4 hearsay never acts).
  - K3: 3-attempts/6-max per lever, then the stuck-protocol fires (II.3).
  - K4: He's phone = data-protected (backup current, Dev Mode on, auto-update off pre-pass).
- Live physical risk row (per VIII.7): battery-pool, tunnel churn, USB replug — all recovery drills on the board; equipment-thrash hard-bounded to the session.

## the shred (evidence-belt in one glance)

On hold state 2026-11-01 (see 08-resume for the full belt):
| artifact | tier | one-line |
|---|---|---|
| CVE-2026-112706 file-read | **T-0** | repro'd on-device: mediaplaybackd vended fd stolen GlobalPreferences.plist (2,821 B) |
| 84607 race door open | **T-0** | the census: fix string = 0 hits in both kexts on 23E246, present in 27.0.1 (2 hits) |
| AVE2 client-gate bypass | **T-0** | mode-2 descriptor lie: session created on all money sizes, session-cap wall = dead |
| AVE2 remaining walls | **T-0** | -8971 (record-vs-descriptor) + -12909 (frame-vs-config): both kext-side, before the multiply |
| HEVC/AVD probe | built · queue | vtdec_hevc_pure + build target wired; needs 1 macOS CI minute |
| cap-pinger | built · queue | bassed in the no-env default of the mode-3 build |
| DPSH/kext diff | T-0 | the sibling's register map (mul w24 w22 w21 + tbnz-neg-only) |
