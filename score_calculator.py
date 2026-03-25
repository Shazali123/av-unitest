# AV-Unitest — Modular Antivirus Benchmark Platform
# Copyright (c) 2026 Shazali. Licensed under GPL-3.0.
"""
Score Calculator — 10-Point Scoring System (60/40 Split)
=========================================================
Scoring breakdown (out of 10 pts total):

    Detection Effectiveness — 6 pts max   (60%)
    System Performance Impact — 4 pts max (40%)

Detection weights (total = 6.0 pts)
------------------------------------
  Layer 1 — EICAR    : 1.0 pt    binary (detected or not)
            Simple signature test — drop a known test file
  Layer 2 — GoPhish  : 1.0 pt    binary (detected or not)
            Phishing simulation with URL blocking + credential capture
  Layer 3 — Atomic   : 2.0 pts   split across N ATT&CK sub-tests
            Real MITRE ATT&CK techniques — rigorous component
  Layer 4 — ABAE     : 2.0 pts   split across N behavioral sub-tests
            Behavioral detection — weighted higher because it is
            the modern standard for advanced endpoint protection

Performance sub-scores (total = 4.0 pts)
------------------------------------------
  CPU Peak/Average  : 1.5 pts   (start at 1.5, deduct by overhead)
  RAM Consumption   : 1.5 pts   (start at 1.5, deduct by overhead)
  Disk I/O / Latency: 1.0 pt    (start at 1.0, deduct by overhead)

  Calibration targets (same standard for all AVs):
    Light AV  (~20% CPU, ~100 MB RAM)  → ~3.60 / 4.0
    Mid   AV  (~40% CPU, ~250 MB RAM)  → ~2.85 / 4.0
    Heavy AV  (~70% CPU, ~400 MB RAM)  → ~1.75 / 4.0

Detection weights rationale
----------------------------
EICAR is the simplest possible test (a known static signature).
GoPhish tests active URL blocking and credential harvesting prevention.
Atomic Red Team covers multiple MITRE ATT&CK techniques.
ABAE evaluates signature-independent behavioral detection, weighted
highest alongside Atomic because behavioral analysis represents the
modern standard for endpoint protection.
"""

# ---------------------------------------------------------------------------
# Detection weight constants — adjust here to tweak scoring model
# ---------------------------------------------------------------------------
WEIGHT_EICAR   = 1.0    # binary: 0 or 1.0
WEIGHT_GOPHISH = 1.0    # binary: 0 or 1.0
WEIGHT_ATOMIC  = 2.0    # split across N sub-tests
WEIGHT_ABAE    = 2.0    # split across N sub-tests

# Performance sub-score ceilings
PERF_CPU_MAX   = 1.5
PERF_RAM_MAX   = 1.5
PERF_DISK_MAX  = 1.0
PERF_TOTAL_MAX = PERF_CPU_MAX + PERF_RAM_MAX + PERF_DISK_MAX  # 4.0

# These names are matched against module result['name'] (case-insensitive)
_EICAR_KEYS   = ("eicar",)
_GOPHISH_KEYS = ("gophish", "phish")
_ATOMIC_KEYS  = ("atomic",)
_ABAE_KEYS    = ("abae", "behavioral", "behavioural")


def _module_type(name: str) -> str:
    """Return 'eicar', 'gophish', 'atomic', 'abae', or 'unknown'."""
    n = name.lower()
    if any(k in n for k in _EICAR_KEYS):   return "eicar"
    if any(k in n for k in _GOPHISH_KEYS): return "gophish"
    if any(k in n for k in _ATOMIC_KEYS):  return "atomic"
    if any(k in n for k in _ABAE_KEYS):    return "abae"
    return "unknown"


def calculate_scores(module_results: list) -> dict:
    """
    Compute the 10-point Total Score from a list of module result dicts.

    Parameters
    ----------
    module_results : list of dicts (each is a module's get_results() output)

    Returns
    -------
    dict with keys:
        detection_score   float  0.0–6.0
        performance_score float  0.0–4.0
        total_score       float  0.0–10.0
        breakdown         dict   raw inputs used for transparency
    """
    if not module_results:
        return _zero_scores()

    # ------------------------------------------------------------------ #
    # 1. Detection Score (weighted, 6 pts max)                            #
    # ------------------------------------------------------------------ #
    eicar_score   = 0.0
    gophish_score = 0.0
    atomic_score  = 0.0
    abae_score    = 0.0

    eicar_detected   = False
    gophish_detected = False
    atomic_det       = 0
    atomic_total     = 0
    abae_det         = 0
    abae_total       = 0
    abae_verdict     = "NOT RUN"

    for r in module_results:
        mtype = _module_type(r.get("name", ""))

        if mtype == "eicar":
            eicar_detected = r.get("detected", False)
            eicar_score    = WEIGHT_EICAR if eicar_detected else 0.0

        elif mtype == "gophish":
            gophish_detected = r.get("detected", False)
            gophish_score    = WEIGHT_GOPHISH if gophish_detected else 0.0

        elif mtype == "atomic":
            subs = r.get("test_results", [])
            if subs:
                atomic_det   = sum(1 for s in subs if s.get("detected", False))
                atomic_total = len(subs)
                per_test     = WEIGHT_ATOMIC / atomic_total
                atomic_score = round(atomic_det * per_test, 4)
            else:
                atomic_det   = 1 if r.get("detected", False) else 0
                atomic_total = 1
                atomic_score = WEIGHT_ATOMIC if r.get("detected", False) else 0.0

        elif mtype == "abae":
            abae_verdict = r.get("abae_verdict", "NOT RUN")
            subs = r.get("test_results", [])
            if subs:
                abae_det   = sum(1 for s in subs if s.get("detected", False))
                abae_total = len(subs)
                per_test   = WEIGHT_ABAE / abae_total
                abae_score = round(abae_det * per_test, 4)
            else:
                abae_det   = 1 if r.get("detected", False) else 0
                abae_total = 1
                abae_score = WEIGHT_ABAE if r.get("detected", False) else 0.0

    detection_score = round(eicar_score + gophish_score + atomic_score + abae_score, 2)

    # ------------------------------------------------------------------ #
    # 2. Performance Score (4 pts max)                                    #
    #    Three independent sub-scores, each deducted from its ceiling.    #
    # ------------------------------------------------------------------ #
    cpu_avgs    = []
    cpu_peaks   = []
    ram_peaks   = []
    disk_writes = []

    for r in module_results:
        m = r.get("metrics", {})
        if m.get("cpu_avg") is not None:
            cpu_avgs.append(m["cpu_avg"])
        if m.get("cpu_peak") is not None:
            cpu_peaks.append(m["cpu_peak"])
        if m.get("ram_peak") is not None:
            ram_peaks.append(m["ram_peak"])
        if m.get("disk_write_mb") is not None:
            disk_writes.append(m["disk_write_mb"])

    agg_cpu_avg     = round(sum(cpu_avgs) / len(cpu_avgs), 2) if cpu_avgs    else 0.0
    agg_cpu_peak    = round(max(cpu_peaks), 2)                 if cpu_peaks   else 0.0
    agg_ram_peak_mb = round(max(ram_peaks), 2)                 if ram_peaks   else 0.0
    agg_disk_write  = round(sum(disk_writes), 2)               if disk_writes else 0.0

    # CPU sub-score (1.5 max) — deduct based on average CPU overhead
    #   At 100% avg CPU → lose all 1.5 pts
    cpu_sub = max(0.0, min(PERF_CPU_MAX, PERF_CPU_MAX - agg_cpu_avg * 0.015))

    # RAM sub-score (1.5 max) — deduct based on peak RAM (MB)
    #   At 500 MB peak → lose all 1.5 pts
    ram_sub = max(0.0, min(PERF_RAM_MAX, PERF_RAM_MAX - agg_ram_peak_mb * 0.003))

    # Disk sub-score (1.0 max) — deduct based on disk write (MB)
    #   At 500 MB write → lose all 1.0 pts
    disk_sub = max(0.0, min(PERF_DISK_MAX, PERF_DISK_MAX - agg_disk_write * 0.002))

    performance_score = round(cpu_sub + ram_sub + disk_sub, 2)

    # ------------------------------------------------------------------ #
    # 3. Total Score                                                      #
    # ------------------------------------------------------------------ #
    total_score = round(detection_score + performance_score, 2)

    return {
        "detection_score":   detection_score,
        "performance_score": performance_score,
        "total_score":       total_score,
        # Keep physical_total as alias for backward compatibility with DB/PHP
        "physical_total":    total_score,
        "breakdown": {
            "eicar_detected":    eicar_detected,
            "eicar_score":       round(eicar_score, 2),
            "gophish_detected":  gophish_detected,
            "gophish_score":     round(gophish_score, 2),
            "atomic_detected":   atomic_det,
            "atomic_total":      atomic_total,
            "atomic_score":      round(atomic_score, 2),
            "abae_detected":     abae_det,
            "abae_total":        abae_total,
            "abae_score":        round(abae_score, 2),
            "abae_verdict":      abae_verdict,
            "agg_cpu_avg":       agg_cpu_avg,
            "agg_cpu_peak":      agg_cpu_peak,
            "agg_ram_peak_mb":   agg_ram_peak_mb,
            "agg_disk_write_mb": agg_disk_write,
            "cpu_sub_score":     round(cpu_sub, 2),
            "ram_sub_score":     round(ram_sub, 2),
            "disk_sub_score":    round(disk_sub, 2),
        },
    }


def _zero_scores() -> dict:
    return {
        "detection_score":   0.0,
        "performance_score": 0.0,
        "total_score":       0.0,
        "physical_total":    0.0,
        "breakdown": {
            "eicar_detected":    False,
            "eicar_score":       0.0,
            "gophish_detected":  False,
            "gophish_score":     0.0,
            "atomic_detected":   0,
            "atomic_total":      0,
            "atomic_score":      0.0,
            "abae_detected":     0,
            "abae_total":        0,
            "abae_score":        0.0,
            "abae_verdict":      "NOT RUN",
            "agg_cpu_avg":       0.0,
            "agg_cpu_peak":      0.0,
            "agg_ram_peak_mb":   0.0,
            "agg_disk_write_mb": 0.0,
            "cpu_sub_score":     0.0,
            "ram_sub_score":     0.0,
            "disk_sub_score":    0.0,
        },
    }
