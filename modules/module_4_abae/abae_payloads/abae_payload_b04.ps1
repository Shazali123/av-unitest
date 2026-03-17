<#
ABAE PS1 Payload B-04 — Registry Persistence Simulation
=========================================================
STAGE_COUNT: 5
AMSI + AV registry monitor behavioral signals:
  1. PowerShell writing to the REAL Windows startup persistence key
     HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
     This is the #1 most-watched registry key by every Enterprise AV.
  2. A COM class hijacking key written to HKCU:\Software\Classes
  3. Rapid 20-value write/delete churn on a test key (registry storm)
  4. Immediate self-cleanup (mimics stealthy malware covering tracks)

PowerShell accessing these keys via the Registry PSDrive is AMSI-hooked.
The AV's behavioral engine watches the combination of:
  - PowerShell -> Run key write -> (any binary path) = persistence attempt

Stage markers ([STAGE_OK] lines): printed after each phase completes.
Missing markers indicate AV blocked a registry write/read operation.
#>

$ErrorActionPreference = "SilentlyContinue"

$RunKeyPath  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$ComKeyPath  = "HKCU:\Software\Classes\ABAE_BenchmarkCOM"
$StormKey    = "HKCU:\Software\ABAE_StormTest"
$ValueName   = "ABAEBenchmarkTest"
$FakeExePath = Join-Path $env:TEMP "abae_persist.exe"
$ValueData   = "`"$FakeExePath`" --silent --autostart"

# Phase 1: Enumerate existing Run key entries (recon before persistence planting)
$existingEntries = Get-ItemProperty -Path $RunKeyPath -ErrorAction SilentlyContinue
Write-Output ("[B04] Enumerated existing Run key entries: " + ($existingEntries.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count)
Write-Output "[STAGE_OK] phase1_run_key_enum"

# Phase 2: Write to HKCU\..\Run — real startup persistence key
if (-not (Test-Path $RunKeyPath)) {
    New-Item -Path $RunKeyPath -Force | Out-Null
}
$writeOk = $false
try {
    Set-ItemProperty -Path $RunKeyPath -Name $ValueName -Value $ValueData -Type String -ErrorAction Stop
    $writeOk = $true
} catch {}
if ($writeOk) {
    Write-Output "[B04] Persistence key written: $ValueName = $ValueData"
    Write-Output "[STAGE_OK] phase2_run_key_write"
}

# Brief pause — give AV time to react to the startup key write
Start-Sleep -Milliseconds 500

# Phase 3: COM class hijacking key (secondary persistence vector)
$comOk = $false
try {
    New-Item -Path $ComKeyPath -Force -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path $ComKeyPath -Name "BenchmarkData" -Value "ABAE_COM_HIJACK_TEST"
    New-Item -Path "$ComKeyPath\InprocServer32" -Force -ErrorAction Stop | Out-Null
    Set-ItemProperty -Path "$ComKeyPath\InprocServer32" -Name "(Default)" -Value $FakeExePath
    $comOk = $true
} catch {}
if ($comOk) {
    Write-Output "[B04] COM hijack key planted."
    Write-Output "[STAGE_OK] phase3_com_hijack"
}

# Phase 4: Registry churn — 20 rapid writes/deletes on a test key (storm signal)
$stormOk = $false
try {
    New-Item -Path $StormKey -Force -ErrorAction Stop | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        Set-ItemProperty -Path $StormKey -Name "abae_val_$i" -Value ([System.Guid]::NewGuid().ToString())
        Start-Sleep -Milliseconds 10
    }
    for ($i = 0; $i -lt 20; $i++) {
        Remove-ItemProperty -Path $StormKey -Name "abae_val_$i" -ErrorAction SilentlyContinue
    }
    $stormOk = $true
} catch {}
if ($stormOk) { Write-Output "[STAGE_OK] phase4_registry_storm" }

# Phase 5: Self-cleanup (mimics stealthy malware removing traces)
Remove-ItemProperty -Path $RunKeyPath  -Name $ValueName  -ErrorAction SilentlyContinue
Remove-Item        -Path $ComKeyPath   -Recurse -Force   -ErrorAction SilentlyContinue
Remove-Item        -Path $StormKey     -Recurse -Force   -ErrorAction SilentlyContinue
Write-Output "[B04] Self-cleanup complete."
Write-Output "[STAGE_OK] phase5_cleanup"

Write-Output "PAYLOAD_COMPLETE"
