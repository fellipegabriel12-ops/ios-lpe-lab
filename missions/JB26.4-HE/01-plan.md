# 01-plan.md — JB26.4-HE (Magna rules III.7 / IX.1 / XIV.1)

## objective (one-breath)

`A sandboxed app on the iPhone 16 Pro (iOS 26.4, 23E246) reaches root + a userland jailbreak (Bootstrap/ElleKit), all stages reproducible on-device.`

## theory of victory (the chain)

1. **A — userland CE (their)** CVE-2026-86950 CoreGraphics PDF/TTF OOB write → app code exec. [Status: the pipeline works; CGDEC harness needs the pure-C port of my verdict (their 26.4 path)].
2. **B — sandbox escape (their)** CVE-2026-64740/28995. [untouched, live]. *Our addition:* **CVE-2026-112706 file-read = stage B-2** — LIVE on T-0 — it covers every read the chain needs on the user side.
3. **C — kernel exec (their)** CVE-2026-64747 decoder (the AVE2 multiplies family, mapped) **+ the 84607 race door (T-0 census-confirmed open)**.
4. **D — physrw → uid 0** (their object-replacement, zero PPL-page writes — the M5/Calif-class pattern).
5. **E — bootstrap (mine)** ElleKit/Procursus delivery + the BaseBin stack borrow (already cloned: launchdhook/systemhook/tr创投/AMFI).
6. **F — persistence** — the realistic 26.4 tier = semi-tethered re-apply at boot.

## the kill-switch / AMPUTATE-HERE rows

| id | condition | action |
|---|---|---|
| H1 | the device fails to boot twice after any trigger | resume stage-C only after bootloop policy (no burn) |
| H2 | CI minutes die past 3 resets | waiting-room holds; the census + kcache-lane carry on (zero-CI) |
| H3 | Apple builds a 26.4.1 band = the CVE shelves patch | mission pivots to 27.0.1 band (census already running) |
| K1 | ANY op risks flashing/bootloader | hard no — ODA only |

## ROI-ranked levers (current)

| rank | lever | state | ROI (E[v]/(time×risk×comp)) |
|---|---|---|---|
| 1 | 112706 → `/usr/libexec` dir-list first (one He tap) | VERIFIED T-0, in motion | 9.0 |
| 2 | HEVC/AVD probe (1 CI minute) | ready · queue | 7.5 |
| 3 | multiplies census Q3 (the unpublished decoder class) | running offline | 7.0 |
| 4 | 84607 race harness (their lane) | designed, not built | 6.5 |
| 5 | the 23E246 offset-resolver run (BaseBin pattern scanner) | ready, module | 6.0 |
| 6 | suid-race/pipe-family probes (t_reslide port) | contract pending offsets | 5.0 |
| 7 | CGDEC pure-C port (stage-A on-device) | awaiting CI | 4.5 |

## plan-B rows (the top-2 risks)

- risk: `AppleAVD-side 64747-class walls differ on 26.4k` → plan-B: the AVD-row CVEs (84520/84620/84561 = 5 live CVEs) — the HEVC probe fires a DIFFERENT kext.
- risk: `CI budget exhausted week` → plan-B: all remaining build-lane work goes the zero-CI route (kcache pattern-scanner local, offline census) — no stop.

## cadence

- nightly: board sweep + the waiting-room trigger check (L-243).
- per-shot: board update (Twitter/post mortem = any crash file = evidence).
- weekly: the constitution stress-test + the ARMS-RACE matrix review.
