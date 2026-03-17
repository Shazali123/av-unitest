<#
ABAE PS1 Payload B-03 — Rapid Process Chain + Recon
=====================================================
STAGE_COUNT: 4
AMSI behavioral signals:
  1. PowerShell spawning 50 rapid child cmd.exe processes (burst pattern)
  2. Each child runs a recon LOLBIN — AMSI flags automated enumeration chains
  3. A 4-level deep process tree mimic (dropper -> loader -> payload chain)
  4. WMIC enumeration (flagged as post-exploitation recon)

Unlike Python's subprocess, PowerShell's Start-Process and Invoke-Expression
are AMSI-hooked — every invocation is analyzed in real-time.

Stage markers ([STAGE_OK] lines): printed after each phase completes.
Missing markers indicate AV killed or blocked the phase.
#>

param(
    [int]$BurstCount    = 50,
    [int]$IntervalMs    = 20
)

$ErrorActionPreference = "SilentlyContinue"

# Recon commands — legitimate LOLBINs, suspicious when automated in a burst
$ReconCmds = @(
    "whoami",
    "hostname",
    "ipconfig /all",
    "net user",
    "systeminfo",
    "tasklist",
    "netstat -ano"
)

# Phase 1: Rapid process burst spawning
$burstOk = $true
for ($i = 0; $i -lt $BurstCount; $i++) {
    $cmd = $ReconCmds[$i % $ReconCmds.Length]
    try {
        $proc = Start-Process -FilePath "cmd.exe" `
            -ArgumentList "/c $cmd > nul 2>&1" `
            -WindowStyle Hidden `
            -PassThru -ErrorAction Stop
    } catch {
        $burstOk = $false
        break
    }
    Start-Sleep -Milliseconds $IntervalMs
}
if ($burstOk) { Write-Output "[STAGE_OK] phase1_process_burst" }

# Phase 2: 4-level deep nested process chain (dropper chain mimic)
try {
    $chainCmd = 'cmd /c "cmd /c "cmd /c "cmd /c whoami > nul""""'
    $chainProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $chainCmd" `
        -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    Write-Output "[STAGE_OK] phase2_process_chain"
} catch {
    # If Start-Process itself throws, AV blocked the execution
}

# Phase 3: WMIC enumeration (common post-exploitation recon pattern)
try {
    $null = & wmic process list brief 2>$null
    $null = & wmic os get Caption,Version,OSArchitecture 2>$null
    Write-Output "[STAGE_OK] phase3_wmic_recon"
} catch {}

# Phase 4: PowerShell Invoke-Expression with encoded content (AMSI string scan)
try {
    $encodedRecon = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process | Select-Object -First 10 | Out-Null'))
    Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedRecon)))
    Write-Output "[STAGE_OK] phase4_iex_encoded"
} catch {}

Write-Output "PAYLOAD_COMPLETE"
