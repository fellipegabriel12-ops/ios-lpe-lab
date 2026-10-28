# o_c_ocr.ps1  (O-C = session "jailbreak 3")
# Windows built-in OCR (WinRT Windows.Media.Ocr) over an image file.
# No install, no python packages, ~30 ms per frame, negligible CPU.
# Used to read the Apple 2FA code off the iPhone's screen without a human in the loop.
#
# Usage:
#   powershell -NoProfile -File o_c_ocr.ps1 -Image <path> [-Digits]
#     -Image  : png/jpg path
#     -Digits : print only the best 6-digit candidate found in the text
param(
    [Parameter(Mandatory=$true)][string]$Image,
    [switch]$Digits
)
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Storage.Streams.IRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
$null = [Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType = WindowsRuntime]

$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($op, $type) {
    $m = $asTaskGeneric.MakeGenericMethod($type)
    $t = $m.Invoke($null, @($op))
    $null = $t.Wait(120000)
    $t.Result
}

$path = (Resolve-Path -LiteralPath $Image).Path
$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($path)) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if (-not $engine) { throw "No OCR engine available for the current user profile languages" }

$result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])

if ($Digits) {
    # Pull 6-digit runs out of every line, score them, print the best.
    $best = $null; $bestScore = -1
    foreach ($line in $result.Lines) {
        $text = $line.Text
        foreach ($m in [regex]::Matches($text, '(?<!\d)(\d{6})(?!\d)')) {
            $cand = $m.Groups[1].Value
            $score = 0
            if ($text -match 'code') { $score += 10 }
            if ($cand -notmatch '^[01]' ) { $score += 2 }   # apple codes rarely start with 0/1
            if ($score -gt $bestScore) { $bestScore = $score; $best = $cand }
        }
    }
    Write-Output $best
} else {
    Write-Output "---TEXT---"
    Write-Output $result.Text
    Write-Output "---LINES---"
    foreach ($line in $result.Lines) {
        $w = $line.Words | ForEach-Object { "{0}@{1},{2},{3}x{4}" -f $_.Text, [int]$_.BoundingRect.X, [int]$_.BoundingRect.Y, [int]$_.BoundingRect.Width, [int]$_.BoundingRect.Height }
        Write-Output ("[{0}] {1}" -f $line.Text, ($w -join ' '))
    }
}
