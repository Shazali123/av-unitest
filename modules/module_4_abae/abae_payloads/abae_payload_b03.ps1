<#
ABAE PS1 Payload B-03 — Rapid Process Chain + Recon
=====================================================
AMSI behavioral signals:
  1. PowerShell spawning 50 rapid child cmd.exe processes (burst pattern)
  2. Each child runs a recon LOLBIN — AMSI flags automated enumeration chains
  3. A 4-level deep process tree mimic (dropper → loader → payload chain)
  4. WMIC enumeration (flagged as post-exploitation recon)

Unlike Python's subprocess, PowerShell's Start-Process and Invoke-Expression
are AMSI-hooked — every invocation is analyzed in real-time.
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
for ($i = 0; $i -lt $BurstCount; $i++) {
    $cmd = $ReconCmds[$i % $ReconCmds.Length]
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c $cmd > nul 2>&1" `
        -WindowStyle Hidden `
        -PassThru
    # Don't wait — fire-and-forget burst (maximum frequency signal)
    Start-Sleep -Milliseconds $IntervalMs
}

# Phase 2: 4-level deep nested process chain (dropper chain mimic)
# python.exe → powershell.exe → cmd.exe → cmd.exe → cmd.exe → cmd.exe
$chainCmd = 'cmd /c "cmd /c "cmd /c "cmd /c whoami > nul""""'
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $chainCmd" -WindowStyle Hidden -Wait

# Phase 3: WMIC enumeration (common post-exploitation recon pattern)
$null = & wmic process list brief 2>$null
$null = & wmic os get Caption,Version,OSArchitecture 2>$null

# Phase 4: PowerShell Invoke-Expression with encoded content (AMSI string scan)
# This is the canonical fileless malware pattern — PS executes a string payload
$encodedRecon = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process | Select-Object -First 10 | Out-Null'))
Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedRecon)))

Write-Output "PAYLOAD_COMPLETE"
