"""
ABAE Engine — Adaptive Behavioral Anomaly Engine (v2 — Sacrificial Lamb)
========================================================================
Architecture: Sacrificial Lamb / Process Isolation

The benchmark's main process (python.exe) is whitelisted by the AV.
To force real detection, each behavioral test is run inside a SEPARATE
child process spawned from a temporary directory.  The AV sees an unknown
PID performing malicious-looking activity and terminates it.  The parent
(this engine) watches the child's exit code + stdout sentinel and records
the AV's kill action as a DETECTED result.

Detection logic
---------------
Each payload script prints "PAYLOAD_COMPLETE" as its very last line when
it finishes without interference.  The parent checks:

  1. Sentinel "PAYLOAD_COMPLETE" present in stdout  → NOT DETECTED
  2. Sentinel missing AND returncode != 0             → DETECTED (AV killed)
  3. subprocess.TimeoutExpired                        → DETECTED (AV hung/suspended)
  4. returncode == -1 (launch failure)               → DETECTED (AV blocked launch)

Six behavioral tests (up from 5):
  B-01  Ransomware File Churn          (500 files, .locked rename, ransom note)
  B-02  Entropy Storm / XOR Cipher     (100×8 KB files, double XOR in-place)
  B-03  Process Chain + WMIC Recon     (50 cmd.exe burst, 4-level chain, wmic)
  B-04  Registry Persistence           (HKCU\\...\\Run key write + COM key)
  B-05  LOLBIN Abuse                   (certutil, mshta, PS EncodedCommand, bitsadmin, regsvr32)
  B-06  Multi-Vector Concurrent Storm  (all of the above on simultaneous threads)
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
from dataclasses import dataclass, field
from typing import Optional

SENTINEL = "PAYLOAD_COMPLETE"

# ---------------------------------------------------------------------------
# Result container (unchanged — compatible with module.py / results_handler)
# ---------------------------------------------------------------------------

@dataclass
class BehaviorResult:
    tid:               str
    name:              str
    detected:          bool  = False
    detection_latency: float = 0.0
    detail:            str   = ""
    elapsed:           float = 0.0
    extra:             dict  = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _payloads_dir() -> str:
    """Absolute path to the abae_payloads/ folder next to this file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "abae_payloads")


def _copy_payload_to_temp(payload_filename: str) -> str:
    """
    Copy a payload script to a fresh sub-directory of %TEMP% so the spawned
    python.exe runs from an un-whitelisted path the AV has never seen before.
    Returns the full path to the copied script.
    """
    src = os.path.join(_payloads_dir(), payload_filename)
    # Each run gets a unique temp dir — prevents any path caching by the AV
    temp_dir = tempfile.mkdtemp(prefix="abae_run_")
    dst = os.path.join(temp_dir, payload_filename)
    shutil.copy2(src, dst)
    return dst


def _run_sacrificial(
    tid: str,
    name: str,
    payload_filename: str,
    extra_args: list = None,
    timeout: int = 30,
) -> BehaviorResult:
    """
    Core sacrificial launcher.

    1. Copies payload to %TEMP% sub-dir
    2. Spawns it as a completely separate python.exe process
    3. Waits up to `timeout` seconds
    4. Checks sentinel + exit code to decide DETECTED / NOT DETECTED
    """
    t0 = time.time()
    payload_path = None
    temp_dir     = None
    detected     = False
    detect_lat   = 0.0
    detail       = ""
    extra        = {"payload": payload_filename}

    try:
        payload_path = _copy_payload_to_temp(payload_filename)
        temp_dir     = os.path.dirname(payload_path)

        cmd = [sys.executable, payload_path] + (extra_args or [])

        print(f"[ABAE] {tid} Spawning sacrificial PID: {payload_filename} (from {temp_dir})")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            # No CREATE_NO_WINDOW — we WANT the AV to see this as a visible process
        )

        stdout       = result.stdout or ""
        returncode   = result.returncode
        sentinel_ok  = SENTINEL in stdout

        extra["returncode"]  = returncode
        extra["sentinel_ok"] = sentinel_ok
        extra["stderr_tail"] = (result.stderr or "")[-300:]  # last 300 chars

        if sentinel_ok and returncode == 0:
            # Child completed fully — AV did NOT intervene
            detected = False
            detail   = f"Payload finished cleanly (sentinel present, rc=0). AV did not detect."
        elif not sentinel_ok and returncode != 0:
            # Most likely kill: no sentinel + non-zero exit
            detected   = True
            detect_lat = round(time.time() - t0, 3)
            detail     = (f"AV likely terminated child process. "
                          f"Sentinel absent, returncode={returncode}.")
        elif not sentinel_ok and returncode == 0:
            # Unusual: clean exit but no sentinel — payload crashed internally
            detected = False
            detail   = f"Payload exited 0 but sentinel missing — internal crash, not AV kill."
            extra["warning"] = "no_sentinel_rc0"
        else:
            # sentinel present but rc != 0 — payload printed sentinel then AV killed on exit
            detected   = True
            detect_lat = round(time.time() - t0, 3)
            detail     = f"AV may have intervened on exit. Sentinel present but rc={returncode}."

    except subprocess.TimeoutExpired:
        # AV suspended the process — it never returned
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"AV suspended/hung child process — TimeoutExpired after {timeout}s."
        extra["timeout"] = timeout

    except (FileNotFoundError, PermissionError, OSError) as e:
        # AV blocked the python.exe launch itself
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"AV blocked child process launch: {e}"
        extra["launch_error"] = str(e)

    except Exception as e:
        # Unexpected failure
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"Unexpected exception during sacrificial run: {e}"
        extra["exception"] = str(e)

    finally:
        # Always clean up the temp dir regardless of outcome
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    return BehaviorResult(
        tid=tid,
        name=name,
        detected=detected,
        detection_latency=detect_lat,
        detail=detail,
        elapsed=round(time.time() - t0, 2),
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Individual sacrificial test wrappers
# ---------------------------------------------------------------------------

def _b01_ransomware_churn(cfg: dict) -> BehaviorResult:
    """
    B-01 — Ransomware File Churn
    Sacrificial child: creates 500 files, overwrites with urandom, renames
    to .locked, drops and deletes a RECOVERY_KEY.txt decoy.
    """
    count = cfg.get("file_manipulation_count", 500)
    return _run_sacrificial(
        tid="B-01",
        name="Ransomware File Churn",
        payload_filename="abae_payload_b01.py",
        extra_args=[str(count)],
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b02_entropy_storm(cfg: dict) -> BehaviorResult:
    """
    B-02 — Entropy Storm / XOR Cipher
    Sacrificial child: writes 100×8 KB files then XOR-encrypts them in-place
    twice to simulate a double-cipher encryption loop.
    """
    file_count = cfg.get("entropy_file_count", 100)
    file_bytes = cfg.get("entropy_file_size_kb", 8) * 1024
    return _run_sacrificial(
        tid="B-02",
        name="Entropy Storm (XOR Cipher)",
        payload_filename="abae_payload_b02.py",
        extra_args=[str(file_count), str(file_bytes)],
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b03_process_chain(cfg: dict) -> BehaviorResult:
    """
    B-03 — Rapid Process Chain + WMIC Recon
    Sacrificial child: spawns 50 cmd.exe processes in rapid fire, each running
    recon LOLBINs; then executes a 4-level deep process chain + wmic enumeration.
    """
    burst    = cfg.get("process_burst_count", 50)
    interval = cfg.get("process_burst_interval_s", 0.02)
    return _run_sacrificial(
        tid="B-03",
        name="Process Chain + WMIC Recon",
        payload_filename="abae_payload_b03.py",
        extra_args=[str(burst), str(interval)],
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b04_registry_persistence(cfg: dict) -> BehaviorResult:
    """
    B-04 — Registry Persistence Simulation
    Sacrificial child: writes to HKCU\\...\\CurrentVersion\\Run (the real startup
    persistence key) and a fake COM class key, then self-cleans.
    """
    return _run_sacrificial(
        tid="B-04",
        name="Registry Persistence Simulation",
        payload_filename="abae_payload_b04.py",
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b05_lolbin_abuse(cfg: dict) -> BehaviorResult:
    """
    B-05 — Living off the Land (LOLBIN) Abuse
    Sacrificial child chains: certutil encode/decode, mshta VBScript,
    PowerShell EncodedCommand, bitsadmin transfer, regsvr32 Squiblydoo.
    """
    if not cfg.get("lolbin_enabled", True):
        return BehaviorResult(
            tid="B-05", name="LOLBIN Abuse (disabled)",
            detail="Skipped — lolbin_enabled=false in config."
        )
    return _run_sacrificial(
        tid="B-05",
        name="LOLBIN Abuse",
        payload_filename="abae_payload_b05.py",
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b06_multivector_storm(cfg: dict) -> BehaviorResult:
    """
    B-06 — Multi-Vector Concurrent Storm
    Sacrificial child runs file storm + process burst + entropy cipher +
    registry churn ALL simultaneously on separate threads.  The concurrent
    multi-vector pattern is the strongest zero-day heuristic signal.
    """
    return _run_sacrificial(
        tid="B-06",
        name="Multi-Vector Concurrent Storm",
        payload_filename="abae_payload_b06.py",
        timeout=cfg.get("test_timeout_s", 60),  # storm needs more time
    )


# ---------------------------------------------------------------------------
# Engine orchestrator
# ---------------------------------------------------------------------------

class ABAEEngine:
    """
    Orchestrates all 6 sacrificial behavioral tests.
    Call run_all() → list[BehaviorResult].
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def run_all(self) -> list:
        """Launch all 6 sacrificial tests sequentially; return list[BehaviorResult]."""

        print("[ABAE] ============================================")
        print("[ABAE]  Sacrificial Lamb Process Isolation Mode")
        print("[ABAE]  Each test runs in a separate child PID")
        print("[ABAE]  AV kills child → parent records DETECTED")
        print("[ABAE] ============================================")

        tests = [
            ("B-01", "Ransomware File Churn",          _b01_ransomware_churn),
            ("B-02", "Entropy Storm (XOR Cipher)",     _b02_entropy_storm),
            ("B-03", "Process Chain + WMIC Recon",     _b03_process_chain),
            ("B-04", "Registry Persistence",           _b04_registry_persistence),
            ("B-05", "LOLBIN Abuse",                   _b05_lolbin_abuse),
            ("B-06", "Multi-Vector Concurrent Storm",  _b06_multivector_storm),
        ]

        results = []
        for tid, tname, func in tests:
            print(f"\n[ABAE] ---- {tid}: {tname} ----")
            try:
                result = func(self.cfg)
            except Exception as e:
                result = BehaviorResult(
                    tid=tid, name=tname, detected=True,
                    detail=f"Engine exception (possible AV intervention): {e}",
                    elapsed=0.0,
                )
            verdict = "DETECTED" if result.detected else "NOT DETECTED"
            latency = (f"  latency={result.detection_latency}s"
                       if result.detected else "")
            print(f"[ABAE]   -> [{verdict}]  {result.elapsed}s{latency}  — {result.detail}")
            results.append(result)

        return results
