<#
ABAE PS1 Payload B-01 — Ransomware File Churn
==============================================
STAGE_COUNT: 4
Executed by PowerShell via AMSI.
AMSI intercepts this at the script engine level — not at the process level.
Every line of this script is scanned in real-time by the AV's AMSI provider.

Behavioral signals:
  1. Rapidly creates 500 files with realistic document names
  2. Overwrites content with high-entropy random bytes (simulated encryption)
  3. Renames all files to .locked extension (ransomware extension marker)
  4. Drops a RECOVERY_KEY.txt decoy then deletes it (ransom note lifecycle)
  5. Outputs PAYLOAD_COMPLETE sentinel at end

If AMSI or the AV terminates this script before line 1, the sentinel
is never emitted and the parent Python process records DETECTED.

Stage markers ([STAGE_OK] lines): printed after each phase completes.
Missing markers indicate AV quarantined a phase mid-execution.
#>

param([int]$FileCount = 500)

$ErrorActionPreference = "Stop"
$StageDir = Join-Path $env:TEMP ("abae_b01_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

try {
    $paths = @()

    # Phase 1: Rapid file creation with realistic document names
    for ($i = 0; $i -lt $FileCount; $i++) {
        $fname = Join-Path $StageDir ("document_{0:D4}.docx" -f $i)
        [System.IO.File]::WriteAllText($fname, ("CONFIDENTIAL REPORT DATA SECTION " * 120))
        $paths += $fname
    }
    Write-Output "[STAGE_OK] phase1_file_creation"

    # Phase 2: In-place high-entropy overwrite (encryption simulation)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    foreach ($p in $paths) {
        $buf = [byte[]]::new(4096)
        $rng.GetBytes($buf)
        [System.IO.File]::WriteAllBytes($p, $buf)
    }
    $rng.Dispose()
    Write-Output "[STAGE_OK] phase2_entropy_overwrite"

    # Phase 3: Extension swap .docx -> .locked (ransomware marker)
    foreach ($p in $paths) {
        $newPath = $p -replace "\.docx$", ".locked"
        Move-Item -LiteralPath $p -Destination $newPath -Force
    }
    Write-Output "[STAGE_OK] phase3_extension_swap"

    # Phase 4: Ransom note drop + immediate delete (self-cleanup mimic)
    $notePath = Join-Path $StageDir "RECOVERY_KEY.txt"
    $noteContent = @"
YOUR FILES HAVE BEEN ENCRYPTED.
Send 0.5 BTC to recover your data.
Contact: abae_benchmark_test@localhost
YOUR UNIQUE ID: $([System.Guid]::NewGuid().ToString())
"@
    [System.IO.File]::WriteAllText($notePath, $noteContent)
    Start-Sleep -Milliseconds 200
    Remove-Item -LiteralPath $notePath -Force
    Write-Output "[STAGE_OK] phase4_ransom_note"

} finally {
    Remove-Item -Recurse -Force -Path $StageDir -ErrorAction SilentlyContinue
}

Write-Output "PAYLOAD_COMPLETE"
