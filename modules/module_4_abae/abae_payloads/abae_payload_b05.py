"""
ABAE Payload B-05 — Living off the Land (LOLBIN) Abuse
=======================================================
Sacrificial process: spawned by abae_engine.py from %TEMP%.

LOLBINs (Living off the Land Binaries) are legitimate Windows system tools
that malware abuses to evade signature detection.  This payload chains
several LOLBIN techniques that modern zero-day threats use.

Techniques:
  1. certutil.exe -encode   — file encoding (used to obfuscate malware drops)
  2. certutil.exe -decode   — decode it back (full encode/decode cycle)
  3. mshta.exe vbscript     — HTML Application engine executing inline script
  4. regsvr32 /s /n /u /i   — Squiblydoo technique (regsvr32 remote script load)
  5. PowerShell EncodedCommand — Base64-encoded PS command execution
  6. bitsadmin /transfer    — BITS service abuse (used for covert downloads)

Each technique is run with a benign payload (e.g., whoami output) but the
EXECUTION PATTERN itself is what triggers behavioural AV heuristics —
not the payload content.
"""

import os
import sys
import base64
import tempfile
import subprocess
import shutil

SENTINEL         = "PAYLOAD_COMPLETE"
CREATE_NO_WINDOW = 0x08000000


def _run(cmd: list, timeout: int = 15):
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=CREATE_NO_WINDOW
        )
        return r.returncode, r.stdout.strip()
    except subprocess.TimeoutExpired:
        return -2, "TIMEOUT"
    except Exception as e:
        return -1, str(e)


def phase1_certutil_encode_decode(stage_dir: str):
    """
    certutil.exe -encode / -decode cycle.
    Certutil is commonly used by malware to base64-encode dropper payloads.
    The full encode→decode cycle mimics a dropper unpacking its next stage.
    """
    source_file  = os.path.join(stage_dir, "source.txt")
    encoded_file = os.path.join(stage_dir, "encoded.b64")
    decoded_file = os.path.join(stage_dir, "decoded.txt")

    with open(source_file, "w") as f:
        f.write("ABAE_BENCHMARK_LOLBIN_PAYLOAD" * 10)

    _run(["certutil", "-encode", source_file, encoded_file])
    _run(["certutil", "-decode", encoded_file, decoded_file])

    if os.path.exists(decoded_file):
        print("[B05] certutil encode/decode cycle complete.", flush=True)
    else:
        print("[B05] certutil: output missing (possible AV block).", flush=True)


def phase2_mshta_vbscript():
    """
    mshta.exe executing inline VBScript.
    Mshta is frequently abused to run scripts without writing to disk.
    The VBScript here simply calls CreateObject("WScript.Shell") and runs
    a benign whoami command — but the call pattern is a strong AV signal.
    """
    # Inline VBScript that runs whoami and closes — no file written to disk
    vbs = 'vbscript:Execute("CreateObject(""WScript.Shell"").Run ""whoami > nul"",0:close")'
    rc, _ = _run(["mshta.exe", vbs], timeout=8)
    print(f"[B05] mshta vbscript executed (rc={rc}).", flush=True)


def phase3_powershell_encoded():
    """
    PowerShell -EncodedCommand execution.
    Base64-encoded PowerShell is the most common obfuscation technique used
    by fileless malware and living-off-the-land attacks.
    Command: Get-Process | Select-Object -First 5
    """
    ps_command  = "Get-Process | Select-Object -First 5 | Out-Null"
    encoded_cmd = base64.b64encode(ps_command.encode("utf-16-le")).decode("ascii")
    rc, _ = _run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-WindowStyle", "Hidden", "-EncodedCommand", encoded_cmd],
        timeout=15
    )
    print(f"[B05] PowerShell EncodedCommand executed (rc={rc}).", flush=True)


def phase4_bitsadmin_transfer(stage_dir: str):
    """
    bitsadmin /transfer — BITS service abuse.
    BITS is a legitimate Windows service used by Windows Update.
    Malware abuses it to download payloads silently, bypassing firewall rules.
    We transfer a local file (no network) to trigger the BITS pattern.
    """
    source = os.path.join(stage_dir, "bits_source.txt")
    dest   = os.path.join(stage_dir, "bits_dest.txt")

    with open(source, "w") as f:
        f.write("ABAE_BITS_TEST")

    # Use file:// URI — purely local, no network call
    source_uri = f"file:///{source.replace(os.sep, '/')}"
    rc, _ = _run(
        ["bitsadmin", "/transfer", "ABAEJob", source_uri, dest],
        timeout=10
    )
    print(f"[B05] bitsadmin transfer executed (rc={rc}).", flush=True)


def phase5_regsvr32_squiblydoo():
    """
    Squiblydoo: regsvr32 /s /n /u /i:<URL> scrobj.dll
    Normally used to load a remote COM scriptlet without writing to disk.
    We use a localhost URL (no real server) — the command pattern is the signal.
    """
    rc, _ = _run(
        ["regsvr32", "/s", "/n", "/u", "/i:http://127.0.0.1:1/abae.sct", "scrobj.dll"],
        timeout=5
    )
    # Expected to fail (no server), but the command pattern is still logged by AV
    print(f"[B05] regsvr32 Squiblydoo pattern executed (rc={rc}).", flush=True)


def main():
    stage_dir = tempfile.mkdtemp(prefix="abae_b05_")
    try:
        phase1_certutil_encode_decode(stage_dir)
        phase2_mshta_vbscript()
        phase3_powershell_encoded()
        phase4_bitsadmin_transfer(stage_dir)
        phase5_regsvr32_squiblydoo()
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)

    print(SENTINEL, flush=True)


if __name__ == "__main__":
    main()
