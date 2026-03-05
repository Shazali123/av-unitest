<#
ABAE PS1 Payload B-04 — Registry Persistence Simulation
=========================================================
AMSI + AV registry monitor behavioral signals:
  1. PowerShell writing to the REAL Windows startup persistence key
     HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
     This is the #1 most-watched registry key by every Enterprise AV.
  2. A COM class hijacking key written to HKCU:\Software\Classes
  3. Rapid 20-value write/delete churn on a test key (registry storm)
  4. Immediate self-cleanup (mimics stealthy malware covering tracks)

PowerShell accessing these keys via the Registry PSDrive is AMSI-hooked.
The AV's behavioral engine watches the combination of:
  - PowerShell → Run key write → (any binary path) = persistence attempt
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

# Phase 2: Write to HKCU\..\Run — real startup persistence key
# This is AMSI/AV's highest-alert action: PS writing an autorun entry
if (-not (Test-Path $RunKeyPath)) {
    New-Item -Path $RunKeyPath -Force | Out-Null
}
Set-ItemProperty -Path $RunKeyPath -Name $ValueName -Value $ValueData -Type String
Write-Output "[B04] Persistence key written: $ValueName = $ValueData"

# Brief pause — give AV time to react to the startup key write
Start-Sleep -Milliseconds 500

# Phase 3: COM class hijacking key (secondary persistence vector)
New-Item -Path $ComKeyPath -Force | Out-Null
Set-ItemProperty -Path $ComKeyPath -Name "BenchmarkData" -Value "ABAE_COM_HIJACK_TEST"
New-Item -Path "$ComKeyPath\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "$ComKeyPath\InprocServer32" -Name "(Default)" -Value $FakeExePath
Write-Output "[B04] COM hijack key planted."

# Phase 4: Registry churn — 20 rapid writes/deletes on a test key (storm signal)
New-Item -Path $StormKey -Force | Out-Null
for ($i = 0; $i -lt 20; $i++) {
    Set-ItemProperty -Path $StormKey -Name "abae_val_$i" -Value ([System.Guid]::NewGuid().ToString())
    Start-Sleep -Milliseconds 10
}
for ($i = 0; $i -lt 20; $i++) {
    Remove-ItemProperty -Path $StormKey -Name "abae_val_$i" -ErrorAction SilentlyContinue
}

# Phase 5: Self-cleanup (mimics stealthy malware removing traces)
Remove-ItemProperty -Path $RunKeyPath  -Name $ValueName  -ErrorAction SilentlyContinue
Remove-Item        -Path $ComKeyPath   -Recurse -Force   -ErrorAction SilentlyContinue
Remove-Item        -Path $StormKey     -Recurse -Force   -ErrorAction SilentlyContinue
Write-Output "[B04] Self-cleanup complete."

Write-Output "PAYLOAD_COMPLETE"
