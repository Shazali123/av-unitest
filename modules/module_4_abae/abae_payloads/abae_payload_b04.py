"""
ABAE Payload B-04 — Registry Persistence Simulation
====================================================
Sacrificial process: spawned by abae_engine.py from %TEMP%.

Behaviour simulated (zero-day / signature-free):
  1. Write a value to the REAL Windows startup persistence key:
       HKCU\Software\Microsoft\Windows\CurrentVersion\Run
     This is not a dummy key — it is the exact key malware uses for persistence.
     The value is immediately deleted after verification.
  2. Write a secondary marker to HKCU\Software\Classes (COM hijacking path)
  3. Enumerate existing Run key entries (recon before persistence planting)

Why this is a strong heuristic signal:
  - Writing to \CurrentVersion\Run is the #1 registry-based persistence method
  - AV behavioural engines watch this key at kernel level
  - A process that wasn't launched at startup writing a startup entry → instant flag
  - The self-cleanup afterwards mimics stealthy malware that covers its tracks
"""

import os
import sys
import winreg
import time

SENTINEL   = "PAYLOAD_COMPLETE"
VALUE_NAME = "ABAEBenchmarkTest"
RUN_KEY    = r"Software\Microsoft\Windows\CurrentVersion\Run"
COM_KEY    = r"Software\Classes\ABAE_BenchmarkCOM"


def phase1_enumerate_run_key():
    """Recon: list current startup entries (as malware would before adding itself)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ)
        i = 0
        entries = []
        while True:
            try:
                name, _, _ = winreg.EnumValue(key, i)
                entries.append(name)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
        print(f"[B04] Enumerated {len(entries)} existing Run key entries.", flush=True)
    except Exception as e:
        print(f"[B04] Run key enumeration: {e}", flush=True)


def phase2_plant_persistence():
    """Write a value to HKCU\\...\\Run (the real startup persistence key)."""
    # The target value points to a benign nonexistent path — purely behavioural test.
    fake_payload_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "abae_persist.exe")
    value_data = f'"{fake_payload_path}" --silent'

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
    )
    winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, value_data)

    # Read-back verification
    read_val, _ = winreg.QueryValueEx(key, VALUE_NAME)
    assert read_val == value_data, "Registry write verification failed"
    winreg.CloseKey(key)
    print(f"[B04] Persistence key written: {VALUE_NAME} = {value_data}", flush=True)


def phase3_plant_com_key():
    """Write a fake COM class registration (COM hijacking simulation)."""
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, COM_KEY)
        winreg.SetValueEx(key, "BenchmarkData", 0, winreg.REG_SZ, "ABAE_COM_TEST")
        winreg.CloseKey(key)
        print("[B04] COM hijack key planted.", flush=True)
    except Exception as e:
        print(f"[B04] COM key: {e}", flush=True)


def cleanup():
    """Remove all planted registry keys — immediately after planting."""
    # Remove Run key value
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, VALUE_NAME)
        winreg.CloseKey(key)
        print("[B04] Persistence key removed (self-cleanup).", flush=True)
    except Exception as e:
        print(f"[B04] Cleanup Run key: {e}", flush=True)

    # Remove COM key
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, COM_KEY)
        print("[B04] COM key removed.", flush=True)
    except Exception as e:
        print(f"[B04] Cleanup COM key: {e}", flush=True)


def main():
    phase1_enumerate_run_key()
    phase2_plant_persistence()
    phase3_plant_com_key()
    # Brief pause to give AV time to react to the registry writes
    time.sleep(0.5)
    cleanup()
    print(SENTINEL, flush=True)


if __name__ == "__main__":
    main()
