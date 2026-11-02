Save the whole 26.4 jailbreak effort: the tooling we wrote, the crafted
payloads (exact bytes), and the board/plan/resume docs.

tools/  - the automation built for this run:
  o_c_jb.py            installer orchestrator (vault creds -> Apple login -> stashed 2FA
                       code -> install; retries on 503/-80046, re-mints the anisette
                       identity on throttle, rejects a wrong code on -21669 and waits
                       for the next one)
  o_c_code_watch.py    "the eyes": screenshot -> crop -> Windows OCR -> stash the
                       newest 6-digit 2FA code (never logs screen text)
  o_c_ocr.ps1 / o_c_ocr_server.ps1   Windows built-in OCR, one-shot + persistent host
  o_c_anisette_provision.py           mint a fresh Apple machine identity (writes the
                                      state BEFORE verifying - the original threw
                                      good identities away)
  o_c_adi_probe.py     does an anisette server honour the adi_pb you send it?
  o_c_gs_probe.py      hand-built GrandSlam init -> raw Apple response (separates
                       identity failure / account failure / throttle)
  o_c_fetch.py         CI artifact fetch that VERIFIES (the old path returned 13,767
                       zero bytes and we nearly called it an exploit result)
  o_c_fire.ps1         the fire sequence: push each payload, launch the harness at
                       it, pull the report, check the device, list the crash store
  o_c_channel.py       host<->device HTTP channel (the phone pulls payloads and
                       pushes results back over the LAN)
  o_c_exp.py / o_c_jev.py   clients for the Experiential gateway (Jev decisions,
                       GPT-6 Luna chat); the key is read from EXPLABS_API_KEY only
  o_c_sps_verify.py    parses our own crafted H.264 back and prints every SPS field
  o_c_h264_gen.py (oc_h264_gen.py)   builds the crafted Annex-B streams, including
                       the level/dimension-mismatch ladder
  o_c_aved_hunt.py     is a fix present in OUR binary? (the CVE-2026-84607 test)
  o_c_kext_fleet.py    carves interesting kexts from a kernelcache and censuses
                       26.4 vs 27.0.1
  oc_*.h264            the crafted streams themselves, exact bytes

docs/
  RESUME.md            where to pick up: state, commands, findings, the traps
  PLAN-26.4-CHAIN.md   the chain plan for this build
  JOINT-LOG.md         the append-only board (never delete a failure line)
  COMMS-O2O.md         the older comms board
