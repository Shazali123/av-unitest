# AV-Unitest — Modular Antivirus Benchmark Platform
# Copyright (c) 2026 Shazali. Licensed under GPL-3.0.
"""
Module 4: Adaptive Behavioral Anomaly Engine (ABAE) — Sacrificial Lamb Edition
==============================================================================
Signature-Independent Detection Evaluation Module.

Each behavioral test is run in an ISOLATED CHILD PROCESS spawned from %TEMP%
so the AV cannot whitelist the benchmark's main process.  If the AV kills the
child, the parent observes the missing sentinel and records DETECTED.

Six behavioral dimensions:
    B-01  Ransomware File Churn         (500 files, .locked rename, ransom note)
    B-02  Entropy Storm / XOR Cipher    (100×8 KB, double XOR in-place)
    B-03  Process Chain + WMIC Recon    (50 cmd.exe burst, 4-level chain)
    B-04  Registry Persistence          (HKCU\\...\\Run key + COM class key)
    B-05  LOLBIN Abuse                  (certutil, mshta, PS Encoded, bitsadmin)
    B-06  Multi-Vector Concurrent Storm (all vectors on simultaneous threads)

PASS criteria (from abae_config.json): detect ≥ pass_threshold of 6.
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor

from module_4_abae.abae_engine import ABAEEngine


class ABAEModule(BaseModule):
    """Module 4 — Adaptive Behavioral Anomaly Engine."""

    def __init__(self):
        super().__init__()
        self.name        = "ABAE Behavioral Engine"
        self.description = ("Signature-independent behavioral anomaly detection (Sacrificial Lamb): "
                            "6 zero-day behavioral tests — ransomware churn, entropy storm, "
                            "process chain, registry persistence, LOLBIN abuse, multi-vector storm.")
        self.test_results  = []
        self.abae_verdict  = "NOT RUN"
        self._cfg          = self._load_config()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self) -> dict:
        defaults = {
            "sandbox_dir":                "BME_TEST",
            "file_manipulation_count":    500,
            "entropy_file_count":         100,
            "entropy_file_size_kb":       8,
            "process_burst_count":        50,
            "process_burst_interval_s":   0.02,
            "file_burst_ops":             1000,
            "pass_threshold":             4,
            "behavioral_consistency_runs": 3,
            "entropy_high_threshold":     7.5,
            "test_timeout_s":             30,
            "lolbin_enabled":             True,
        }
        cfg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "abae_config.json"
        )
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r") as f:
                    defaults.update(json.load(f))
                print(f"[ABAE] Config loaded: {cfg_path}")
            except Exception as e:
                print(f"[ABAE] Config load error (using defaults): {e}")
        else:
            print(f"[ABAE] Config not found at {cfg_path} — using defaults.")
        return defaults

    def get_info(self) -> dict:
        return {
            "id":          self.module_id,
            "name":        self.name,
            "description": self.description,
        }

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    def run(self, monitor: SystemMonitor) -> bool:
        start_time = time.time()
        self.status = "Running"
        monitor.start()

        print("[ABAE] ============================================")
        print("[ABAE]  ABAE — Sacrificial Lamb Edition")
        print("[ABAE]  Zero-Day Behavioral Detection Benchmark")
        print("[ABAE]  6 isolated child-process payloads")
        print("[ABAE] ============================================")
        print(f"[ABAE] Pass threshold: {self._cfg['pass_threshold']}/6 detections")
        print()

        # ------ Run engine ------
        engine      = ABAEEngine(self._cfg)
        br_list     = engine.run_all()   # list[BehaviorResult]

        any_detected = False
        threshold    = self._cfg.get("pass_threshold", 3)

        for br in br_list:
            if br.detected and not any_detected:
                monitor.mark_detection()
                any_detected = True

            # Build dict compatible with results_handler
            self.test_results.append({
                "tid":               br.tid,
                "name":              br.name,
                "test":              f"{br.tid}  {br.name}",  # generic fallback label
                "detected":          br.detected,
                "detail":            br.detail,
                "elapsed":           br.elapsed,
                "detection_latency": br.detection_latency,
                "extra":             br.extra,
            })

        # ------ PASS / FAIL verdict ------
        n_det = sum(1 for r in self.test_results if r["detected"])
        self.abae_verdict = "PASS" if n_det >= threshold else "FAIL"

        print()
        print(f"[ABAE] ============================================")
        print(f"[ABAE]  Results: {n_det}/6 behavioral tests DETECTED")
        print(f"[ABAE]  Zero-Day Behavioral Protection: {self.abae_verdict}")
        print(f"[ABAE] ============================================")

        monitor.stop()
        self.detected       = any_detected
        self.execution_time = time.time() - start_time
        self.metrics        = monitor.get_results()
        self.status         = "Completed"
        return True

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def get_results(self) -> dict:
        return {
            "module_id":      self.module_id,
            "name":           self.name,
            "execution_time": round(self.execution_time, 2),
            "status":         self.status,
            "detected":       getattr(self, "detected", False),
            "test_results":   self.test_results,
            "abae_verdict":   self.abae_verdict,
            "metrics":        self.metrics,
        }
