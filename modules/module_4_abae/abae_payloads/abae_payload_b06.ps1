<#
ABAE PS1 Payload B-06 — Multi-Vector Concurrent Storm
======================================================
STAGE_COUNT: 4
The most aggressive PS1 payload.  Runs all behavioral vectors simultaneously
using PowerShell runspaces (true parallel threads within one process).

This is the hardest test for an AV behavioral engine because:
  - ALL signals fire at the exact same time
  - No single action is necessarily malicious — it's the COMBINATION
  - Concurrent runspaces prevent sequential analysis of each behavior
  - The total behavioral "noise" exceeds any individual threshold

Runspaces (parallel threads):
  RS-1: Ransomware file churn (300 files: create -> urandom overwrite -> .locked)
  RS-2: Process burst (30 cmd.exe spawns with recon commands)
  RS-3: XOR cipher loop (50 x 8 KB files, double-pass in-place encryption)
  RS-4: Registry churn (20 rapid write/delete cycles on startup key area)

AMSI scans the entire script block at load time AND monitors each runspace.

Stage markers: each runspace emits its own completion token ("RS1_DONE" etc.)
The engine collects these from stdout to detect partial runspace kills.
[STAGE_OK] is printed once per completed runspace — 4 expected total.
#>

$ErrorActionPreference = "SilentlyContinue"
$StageDir = Join-Path $env:TEMP ("abae_b06_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

# ── Runspace pool setup ────────────────────────────────────────────────────
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, 4)
$RunspacePool.Open()
$Jobs = @()

# ── RS-1: Ransomware File Churn ────────────────────────────────────────────
$RS1_Script = {
    param($BaseDir)
    $dir = Join-Path $BaseDir "storm_files"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $rng   = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $paths = @()
    for ($i = 0; $i -lt 300; $i++) {
        $p = Join-Path $dir ("victim_{0:D4}.docx" -f $i)
        [System.IO.File]::WriteAllText($p, "DATA_BLOCK_" * 400)
        $paths += $p
    }
    foreach ($p in $paths) {
        $buf = [byte[]]::new(4096); $rng.GetBytes($buf)
        [System.IO.File]::WriteAllBytes($p, $buf)
    }
    foreach ($p in $paths) {
        $new = $p -replace "\.docx$", ".locked"
        try { Move-Item -LiteralPath $p -Destination $new -Force } catch {}
    }
    $rng.Dispose()
    "[STAGE_OK] rs1_ransomware_churn"
}

# ── RS-2: Process Burst ────────────────────────────────────────────────────
$RS2_Script = {
    $cmds = @("whoami","hostname","ipconfig /all","net user","systeminfo","tasklist")
    $allOk = $true
    for ($i = 0; $i -lt 30; $i++) {
        $c = $cmds[$i % $cmds.Length]
        try {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $c > nul 2>&1" `
                -WindowStyle Hidden -ErrorAction Stop | Out-Null
        } catch { $allOk = $false }
        Start-Sleep -Milliseconds 20
    }
    if ($allOk) { "[STAGE_OK] rs2_process_burst" }
}

# ── RS-3: XOR Cipher Loop ──────────────────────────────────────────────────
$RS3_Script = {
    param($BaseDir)
    $dir = Join-Path $BaseDir "cipher_files"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $XorKey = [byte[]](0..255 | ForEach-Object { ($_ * 97 + 13) % 256 })
    $rng    = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $paths  = @()
    for ($i = 0; $i -lt 50; $i++) {
        $p = Join-Path $dir ("blob_{0:D3}.dat" -f $i)
        $buf = [byte[]]::new(8192); $rng.GetBytes($buf)
        [System.IO.File]::WriteAllBytes($p, $buf)
        $paths += $p
    }
    $rng.Dispose()
    # Double-pass XOR in-place
    for ($pass = 0; $pass -lt 2; $pass++) {
        foreach ($p in $paths) {
            try {
                $data = [System.IO.File]::ReadAllBytes($p)
                $out  = [byte[]]::new($data.Length)
                for ($j = 0; $j -lt $data.Length; $j++) {
                    $out[$j] = $data[$j] -bxor $XorKey[$j % 256]
                }
                [System.IO.File]::WriteAllBytes($p, $out)
            } catch {}
        }
    }
    "[STAGE_OK] rs3_xor_cipher"
}

# ── RS-4: Registry Churn ──────────────────────────────────────────────────
$RS4_Script = {
    $key = "HKCU:\Software\ABAE_StormConcurrent"
    $ok  = $false
    try {
        New-Item -Path $key -Force -ErrorAction Stop | Out-Null
        for ($i = 0; $i -lt 20; $i++) {
            Set-ItemProperty -Path $key -Name "val_$i" -Value ([System.Guid]::NewGuid().ToString())
            Start-Sleep -Milliseconds 10
        }
        for ($i = 0; $i -lt 20; $i++) {
            Remove-ItemProperty -Path $key -Name "val_$i" -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
        $ok = $true
    } catch {}
    if ($ok) { "[STAGE_OK] rs4_registry_storm" }
}

# ── Launch all runspaces simultaneously ────────────────────────────────────
foreach ($rs_def in @(
    @{ Script = $RS1_Script; Args = @($StageDir) },
    @{ Script = $RS2_Script; Args = @() },
    @{ Script = $RS3_Script; Args = @($StageDir) },
    @{ Script = $RS4_Script; Args = @() }
)) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $RunspacePool
    $null = $ps.AddScript($rs_def.Script)
    foreach ($arg in $rs_def.Args) { $null = $ps.AddArgument($arg) }
    $handle = $ps.BeginInvoke()
    $Jobs += @{ PS = $ps; Handle = $handle }
}

# ── Wait for all runspaces (25s hard cap) and collect stage markers ─────────
$deadline = (Get-Date).AddSeconds(25)
foreach ($job in $Jobs) {
    $remaining = ($deadline - (Get-Date)).TotalMilliseconds
    if ($remaining -gt 0) {
        $null = $job.Handle.AsyncWaitHandle.WaitOne([int]$remaining)
    }
    try {
        $result = $job.PS.EndInvoke($job.Handle)
        # Each runspace returns its [STAGE_OK] string as its pipeline output
        if ($result) { Write-Output $result }
    } catch {}
    $job.PS.Dispose()
}

$RunspacePool.Close()
$RunspacePool.Dispose()

Remove-Item -Recurse -Force -Path $StageDir -ErrorAction SilentlyContinue

Write-Output "PAYLOAD_COMPLETE"
