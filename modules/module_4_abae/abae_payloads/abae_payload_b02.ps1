<#
ABAE PS1 Payload B-02 — Entropy Storm / XOR Cipher Loop
=========================================================
STAGE_COUNT: 3
AMSI behavioral signal: rapid read-modify-write loop using XOR transformation.
This is the exact pattern modern ransomware uses for in-place encryption:
  read plaintext -> encrypt in memory -> write ciphertext back -> next file

The XOR "cipher" is intentionally simple so AMSI pattern-matches the
read-modify-write-loop structure, not the sophistication of the algorithm.

Stage markers ([STAGE_OK] lines): printed after each phase completes.
Missing markers indicate AV quarantined a phase mid-execution.
#>

param(
    [int]$FileCount   = 100,
    [int]$FileSizeKB  = 8
)

$ErrorActionPreference = "SilentlyContinue"
$StageDir = Join-Path $env:TEMP ("abae_b02_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

# XOR key (256 bytes, non-repeating) — simulates a simple symmetric cipher
$XorKey = [byte[]](0..255 | ForEach-Object { ($_ * 137 + 41) % 256 })

function Invoke-XorBytes([byte[]]$Data) {
    $out = [byte[]]::new($Data.Length)
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $out[$i] = $Data[$i] -bxor $XorKey[$i % 256]
    }
    return $out
}

try {
    $rng   = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $paths = @()
    $bytes = $FileSizeKB * 1024

    # Phase 1: Write high-entropy seed files
    for ($i = 0; $i -lt $FileCount; $i++) {
        $p   = Join-Path $StageDir ("enc_{0:D4}.dat" -f $i)
        $buf = [byte[]]::new($bytes)
        $rng.GetBytes($buf)
        [System.IO.File]::WriteAllBytes($p, $buf)
        $paths += $p
    }
    $rng.Dispose()
    Write-Output "[STAGE_OK] phase1_seed_files"

    # Phase 2: XOR in-place (first pass) — read-modify-write encryption loop
    foreach ($p in $paths) {
        $data       = [System.IO.File]::ReadAllBytes($p)
        $encrypted  = Invoke-XorBytes $data
        [System.IO.File]::WriteAllBytes($p, $encrypted)
    }
    Write-Output "[STAGE_OK] phase2_xor_first_pass"

    # Phase 3: Second XOR pass — double-cipher signal (high-scoring heuristic)
    foreach ($p in $paths) {
        $data       = [System.IO.File]::ReadAllBytes($p)
        $encrypted  = Invoke-XorBytes $data
        [System.IO.File]::WriteAllBytes($p, $encrypted)
    }
    Write-Output "[STAGE_OK] phase3_xor_second_pass"

} finally {
    Remove-Item -Recurse -Force -Path $StageDir -ErrorAction SilentlyContinue
}

Write-Output "PAYLOAD_COMPLETE"
