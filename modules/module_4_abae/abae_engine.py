"""
ABAE Engine — Adaptive Behavioral Anomaly Engine (v4 — Three-Layer Detection)
================================================================================
Architecture: Sacrificial Lamb + PowerShell AMSI Handoff + Multi-Layer Verdict

Why PowerShell instead of Python:
    python.exe is a globally trusted, digitally-signed binary. AVs give it a
    "free pass" for behavioural heuristics to avoid breaking developer tools.

    PowerShell, however, is monitored by AMSI (Anti-Malware Scan Interface)
    at TWO levels:
        Level 1 — Script block: the entire .ps1 is scanned BEFORE execution
        Level 2 — Runtime:      Invoke-Expression / dynamic strings scanned live

The engine drops a .ps1 payload to %TEMP% then runs:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -File <path>

Three-Layer Detection (v4)
--------------------------
Layer 1 — Sentinel check (original):
    Payload prints "PAYLOAD_COMPLETE" as its very last line.
    Absent sentinel + rc!=0 = AV killed the entire PS script.

Layer 2 — Stage-count check (NEW):
    Each payload declares STAGE_COUNT: N in its header comment.
    Sub-operations print "[STAGE_OK] <name>" ONLY if they succeed.
    If an AV kills a child process (e.g. regsvr32.exe) without terminating
    the parent script, that stage's marker is absent → DETECTED.

Layer 3 — Windows Security Event Log (NEW):
    After each sub-test, query Windows Defender's operational event log for
    Event IDs 1116 (threat detected) or 1117 (action taken) timestamped
    within the test window. Any match → DETECTED regardless of sentinel.

Detection verdict table:
    Sentinel absent, rc!=0                      → DETECTED (AV killed script)
    Sentinel present, stages missing            → DETECTED (child process kill)
    Sentinel present, all stages OK, event hit  → DETECTED (event log catch)
    Sentinel present, all stages OK, no events  → NOT DETECTED
    TimeoutExpired                              → DETECTED
    Launch blocked                              → DETECTED

Six behavioral tests:
    B-01  Ransomware File Churn           STAGE_COUNT:4
    B-02  Entropy Storm / XOR Cipher      STAGE_COUNT:3
    B-03  Process Chain + Invoke-Expr     STAGE_COUNT:4
    B-04  Registry Persistence + Storm    STAGE_COUNT:5
    B-05  LOLBIN + AMSI String Triggers   STAGE_COUNT:6
    B-06  Concurrent Runspace Storm       STAGE_COUNT:4
"""

import re
import os
import sys
import time
import shutil
import tempfile
import subprocess
from dataclasses import dataclass, field

SENTINEL      = "PAYLOAD_COMPLETE"
STAGE_OK_TAG  = "[STAGE_OK]"
STAGE_COUNT_RE = re.compile(r"STAGE_COUNT:\s*(\d+)")

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
    Copy a payload script (.ps1 or .py) to a unique %TEMP% subdirectory.
    The spawned process runs from an un-whitelisted path the AV has never seen.
    Returns the full path to the copied file.
    """
    src      = os.path.join(_payloads_dir(), payload_filename)
    temp_dir = tempfile.mkdtemp(prefix="abae_run_")
    dst      = os.path.join(temp_dir, payload_filename)
    shutil.copy2(src, dst)
    return dst


# ---------------------------------------------------------------------------
# Layer 3: Windows Security Event Log query
# ---------------------------------------------------------------------------

def _query_defender_events(since_epoch: float) -> list:
    """
    Query the Windows Defender operational event log for threat detection
    events (IDs 1116 = Threat Found, 1117 = Action Taken) that occurred
    at or after `since_epoch` (Unix timestamp).

    Returns a list of event description strings (may be empty).
    Does NOT require administrator rights.
    """
    since_dt = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(since_epoch))
    ps_cmd = (
        f"Get-WinEvent -FilterHashtable @{{"
        f"LogName='Microsoft-Windows-Windows Defender/Operational';"
        f"Id=1116,1117;"
        f"StartTime='{since_dt}'"
        f"}} -ErrorAction SilentlyContinue | "
        f"Select-Object -ExpandProperty Message | "
        f"Select-Object -First 5"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
        )
        out = (result.stdout or "").strip()
        if out:
            return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Core launcher — Three-Layer Detection
# ---------------------------------------------------------------------------

def _run_ps1_sacrificial(
    tid: str,
    name: str,
    payload_ps1: str,
    extra_args: list = None,
    timeout: int = 30,
) -> BehaviorResult:
    """
    PowerShell AMSI Handoff launcher with three-layer detection.

    Layer 1 — Sentinel: PAYLOAD_COMPLETE absent + rc!=0 → DETECTED
    Layer 2 — Stages:   [STAGE_OK] count < STAGE_COUNT → DETECTED
    Layer 3 — EventLog: Defender event 1116/1117 in test window → DETECTED
    """
    t0         = time.time()
    temp_dir   = None
    detected   = False
    detect_lat = 0.0
    detail     = ""
    extra      = {"payload": payload_ps1, "mode": "powershell_amsi_v4"}

    try:
        dst      = _copy_payload_to_temp(payload_ps1)
        temp_dir = os.path.dirname(dst)

        # Read STAGE_COUNT from the payload source
        src_path = os.path.join(_payloads_dir(), payload_ps1)
        expected_stages = 0
        try:
            with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
                header = f.read(1500)   # only scan the header comment
            m = STAGE_COUNT_RE.search(header)
            if m:
                expected_stages = int(m.group(1))
        except Exception:
            pass

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-NonInteractive",
            "-File", dst,
        ] + (extra_args or [])

        print(f"[ABAE] {tid} Spawning PS1 payload via AMSI: {payload_ps1}  "
              f"(expecting {expected_stages} stage markers)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        stdout       = result.stdout or ""
        returncode   = result.returncode
        sentinel_ok  = SENTINEL in stdout

        # ── Layer 2: Stage count check ────────────────────────────────────
        stage_lines  = [ln for ln in stdout.splitlines() if STAGE_OK_TAG in ln]
        stages_found = len(stage_lines)
        stages_missing = max(0, expected_stages - stages_found) if expected_stages > 0 else 0

        # ── Layer 3: Windows Security Event Log ──────────────────────────
        defender_events = _query_defender_events(t0)
        event_hit = len(defender_events) > 0

        extra["returncode"]     = returncode
        extra["sentinel_ok"]    = sentinel_ok
        extra["stages_expected"] = expected_stages
        extra["stages_found"]   = stages_found
        extra["stages_missing"] = stages_missing
        extra["event_log_hits"] = len(defender_events)
        extra["stderr_tail"]    = (result.stderr or "")[-300:]

        detect_lat = round(time.time() - t0, 3)

        # ── Verdict ───────────────────────────────────────────────────────
        if not sentinel_ok and returncode != 0:
            # Layer 1: AV/AMSI killed the entire script
            detected = True
            detail   = (f"[L1] AMSI/AV terminated PowerShell script. "
                        f"Sentinel absent, rc={returncode}. "
                        f"Stderr: {extra['stderr_tail'][:150]}")

        elif sentinel_ok and stages_missing > 0:
            # Layer 2: Script completed but child processes were killed
            detected = True
            detail   = (f"[L2] Surgical child-process termination detected. "
                        f"Sentinel present but {stages_missing}/{expected_stages} "
                        f"stage(s) missing. "
                        f"Found stages: {[l.split(STAGE_OK_TAG)[-1].strip() for l in stage_lines]}")

        elif sentinel_ok and event_hit:
            # Layer 3: Defender logged a threat during the test window
            detected = True
            detail   = (f"[L3] Windows Defender event log hit during test window. "
                        f"{len(defender_events)} event(s) found. "
                        f"Snippet: {defender_events[0][:200]}")

        elif not sentinel_ok and returncode == 0:
            # Script exited clean but sentinel missing — PS internal error, not AV
            detected = False
            detail   = (f"PS1 exited 0 but sentinel missing — "
                        f"likely internal PS error, not AMSI kill. "
                        f"Stages found: {stages_found}/{expected_stages}")
            extra["warning"] = "no_sentinel_rc0"

        elif sentinel_ok and returncode != 0:
            # Sentinel present but non-zero rc — possible AMSI logged + killed on exit
            detected = True
            detail   = f"[L1] AMSI intervention on exit. Sentinel present but rc={returncode}."

        else:
            # All clear
            detected = False
            detail   = (f"PS1 payload completed cleanly. "
                        f"Sentinel ✓, rc=0, stages {stages_found}/{expected_stages}, "
                        f"no Defender events.")
            detect_lat = 0.0

    except subprocess.TimeoutExpired:
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"[L1] AV/AMSI suspended PowerShell script — TimeoutExpired after {timeout}s."
        extra["timeout"] = timeout

    except (FileNotFoundError, PermissionError, OSError) as e:
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"[L1] AV blocked powershell.exe launch: {e}"
        extra["launch_error"] = str(e)

    except Exception as e:
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"Unexpected exception during PS1 run: {e}"
        extra["exception"] = str(e)

    finally:
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


def _run_py_sacrificial(
    tid: str,
    name: str,
    payload_py: str,
    extra_args: list = None,
    timeout: int = 30,
) -> BehaviorResult:
    """
    Fallback Python sacrificial launcher (kept for reference / non-AMSI tests).
    Copies .py payload to %TEMP% and spawns via sys.executable.
    """
    t0         = time.time()
    temp_dir   = None
    detected   = False
    detect_lat = 0.0
    detail     = ""
    extra      = {"payload": payload_py, "mode": "python_sacrificial"}

    try:
        dst      = _copy_payload_to_temp(payload_py)
        temp_dir = os.path.dirname(dst)
        cmd      = [sys.executable, dst] + (extra_args or [])

        print(f"[ABAE] {tid} Spawning Python payload from TEMP: {payload_py}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )

        stdout      = result.stdout or ""
        returncode  = result.returncode
        sentinel_ok = SENTINEL in stdout

        extra["returncode"]  = returncode
        extra["sentinel_ok"] = sentinel_ok
        extra["stderr_tail"] = (result.stderr or "")[-300:]

        if sentinel_ok and returncode == 0:
            detected = False
            detail   = "Python payload completed cleanly — AV did not detect."
        elif not sentinel_ok and returncode != 0:
            detected   = True
            detect_lat = round(time.time() - t0, 3)
            detail     = f"AV terminated Python child. Sentinel absent, rc={returncode}."
        elif not sentinel_ok and returncode == 0:
            detected = False
            detail   = "Python child exited 0 but no sentinel — internal crash."
            extra["warning"] = "no_sentinel_rc0"
        else:
            detected   = True
            detect_lat = round(time.time() - t0, 3)
            detail     = f"AV intervention suspected. Sentinel present but rc={returncode}."

    except subprocess.TimeoutExpired:
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"AV suspended Python child — TimeoutExpired after {timeout}s."
        extra["timeout"] = timeout

    except (FileNotFoundError, PermissionError, OSError) as e:
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"AV blocked Python child launch: {e}"
        extra["launch_error"] = str(e)

    except Exception as e:
        detected   = True
        detect_lat = round(time.time() - t0, 3)
        detail     = f"Unexpected exception: {e}"
        extra["exception"] = str(e)

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    return BehaviorResult(
        tid=tid, name=name, detected=detected,
        detection_latency=detect_lat, detail=detail,
        elapsed=round(time.time() - t0, 2), extra=extra,
    )


# ---------------------------------------------------------------------------
# Individual test wrappers — PS1 primary, Python fallback
# ---------------------------------------------------------------------------

def _b01_ransomware_churn(cfg: dict) -> BehaviorResult:
    """B-01 Ransomware File Churn — PS1 via AMSI (RNGCrypto + .locked rename + ransom note)"""
    return _run_ps1_sacrificial(
        tid="B-01", name="Ransomware File Churn (AMSI)",
        payload_ps1="abae_payload_b01.ps1",
        extra_args=["-FileCount", str(cfg.get("file_manipulation_count", 500))],
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b02_entropy_storm(cfg: dict) -> BehaviorResult:
    """B-02 Entropy Storm / XOR Cipher — PS1 via AMSI (double-pass in-place cipher)"""
    return _run_ps1_sacrificial(
        tid="B-02", name="Entropy Storm / XOR Cipher (AMSI)",
        payload_ps1="abae_payload_b02.ps1",
        extra_args=[
            "-FileCount", str(cfg.get("entropy_file_count", 100)),
            "-FileSizeKB", str(cfg.get("entropy_file_size_kb", 8)),
        ],
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b03_process_chain(cfg: dict) -> BehaviorResult:
    """B-03 Process Chain + Invoke-Expression — PS1 via AMSI (burst + IEX + WMIC)"""
    return _run_ps1_sacrificial(
        tid="B-03", name="Process Chain + Invoke-Expression (AMSI)",
        payload_ps1="abae_payload_b03.ps1",
        extra_args=[
            "-BurstCount", str(cfg.get("process_burst_count", 50)),
            "-IntervalMs",  str(int(cfg.get("process_burst_interval_s", 0.02) * 1000)),
        ],
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b04_registry_persistence(cfg: dict) -> BehaviorResult:
    """B-04 Registry Persistence — PS1 via AMSI (real Run key + COM + registry storm)"""
    return _run_ps1_sacrificial(
        tid="B-04", name="Registry Persistence + Storm (AMSI)",
        payload_ps1="abae_payload_b04.ps1",
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b05_lolbin_amsi(cfg: dict) -> BehaviorResult:
    """B-05 LOLBIN + AMSI String Triggers — certutil/mshta/IEX/bitsadmin/regsvr32/Add-MpPreference"""
    if not cfg.get("lolbin_enabled", True):
        return BehaviorResult(
            tid="B-05", name="LOLBIN + AMSI Strings (disabled)",
            detail="Skipped — lolbin_enabled=false in config."
        )
    return _run_ps1_sacrificial(
        tid="B-05", name="LOLBIN + AMSI String Triggers",
        payload_ps1="abae_payload_b05.ps1",
        timeout=cfg.get("test_timeout_s", 30),
    )


def _b06_concurrent_storm(cfg: dict) -> BehaviorResult:
    """B-06 Concurrent Runspace Storm — all vectors simultaneously via PS runspaces"""
    return _run_ps1_sacrificial(
        tid="B-06", name="Concurrent Runspace Storm (AMSI)",
        payload_ps1="abae_payload_b06.ps1",
        timeout=cfg.get("test_timeout_s", 60),  # storm needs more time
    )


# ---------------------------------------------------------------------------
# Engine orchestrator
# ---------------------------------------------------------------------------

class ABAEEngine:
    """
    Orchestrates all 6 PowerShell AMSI behavioral tests.
    Call run_all() → list[BehaviorResult].
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def run_all(self) -> list:
        """Launch all 6 PS1 sacrificial tests sequentially; return list[BehaviorResult]."""

        print("[ABAE] ============================================================")
        print("[ABAE]  Sacrificial Lamb + PowerShell AMSI Handoff Mode")
        print("[ABAE]  Each test drops a .ps1 to %TEMP% and runs via PS engine")
        print("[ABAE]  AMSI intercepts behavioural patterns at the script level")
        print("[ABAE] ============================================================")

        tests = [
            ("B-01", "Ransomware File Churn (AMSI)",         _b01_ransomware_churn),
            ("B-02", "Entropy Storm / XOR Cipher (AMSI)",    _b02_entropy_storm),
            ("B-03", "Process Chain + Invoke-Expr (AMSI)",   _b03_process_chain),
            ("B-04", "Registry Persistence (AMSI)",          _b04_registry_persistence),
            ("B-05", "LOLBIN + AMSI String Triggers",        _b05_lolbin_amsi),
            ("B-06", "Concurrent Runspace Storm (AMSI)",     _b06_concurrent_storm),
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
            latency = f"  latency={result.detection_latency}s" if result.detected else ""
            print(f"[ABAE]   -> [{verdict}]  {result.elapsed}s{latency}  — {result.detail}")
            results.append(result)

        return results
