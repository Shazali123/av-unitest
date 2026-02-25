# AV Benchmark Testing Framework — Phase 4

Modern GUI application for benchmarking antivirus software across four test layers.

## Quick Start

```powershell
python main.py
```

## Features

- ✅ **GUI Interface** — Modern dark theme using CustomTkinter
- ✅ **Antivirus Detection** — Automatically detects installed AV
- ✅ **Dynamic Modules** — Add modules without code changes
- ✅ **System Monitoring** — Tracks CPU, RAM, Disk I/O per module
- ✅ **Results Export** — Saves detailed reports to TXT files

---

## The 4-Layer Evaluation Stack

| Layer | Module | What It Measures |
|-------|--------|----------------|
| 1 | EICAR Test | Basic signature functionality |
| 2 | GoPhish Simulation | User-layer phishing attack resilience |
| 3 | ATT&CK Simulation | Advanced attack technique detection |
| 4 | ABAE Behavioral Engine | Unknown behavioral anomaly defense |

---

## Modules

### Module 1: EICAR Test ✅ FUNCTIONAL
Standard signature detection test using the EICAR test file.
- Creates EICAR test file on disk
- Monitors for AV quarantine and detection time

### Module 2: GoPhish Phishing Simulation ✅ FUNCTIONAL
Live phishing simulation against a GoPhish server (Ubuntu VM).
- Creates real campaign via GoPhish REST API
- Windows machine simulates victim clicking phishing link (SmartScreen test)
- Downloads phishing page HTML with EICAR JS payload to disk (file scanner test)
- Submits fake credentials (POST exfiltration test)
- Campaign preserved in GoPhish archive after run

Configure: `modules/module_2_gophish/gophish_config.json`

### Module 3: ATT&CK Simulation ✅ FUNCTIONAL
5 live MITRE ATT&CK technique tests (Python stdlib only).

| ATT&CK ID | Technique | AV Target |
|-----------|-----------|-----------|
| T1059.001 | PowerShell encoded `IEX`/`DownloadString` | AMSI / script-block logging |
| T1003.001 | LSASS dump via `comsvcs.dll` (rundll32) | Credential-dumping heuristic |
| T1218.011 | Rundll32 `javascript:` LOLBin | Living-off-the-land heuristic |
| T1105     | EICAR string saved as `.exe` on disk | Real-time file scanner |
| T1082     | Sysinfo recon → base64 stage → loopback exfil | Behavioural chain |

### Module 4: ABAE Behavioral Engine ✅ FUNCTIONAL (Phase 4)
**Adaptive Behavioral Anomaly Engine** — signature-independent detection evaluation.

Evaluates whether the AV detects _abnormal behavior patterns_ without relying on known signatures. Completely original — no open-source tools.

| Test | Dimension | Technique |
|------|-----------|-----------|
| B-01 | Rapid File Manipulation | 300 files overwritten/renamed at high speed (ransomware-like churn) |
| B-02 | Entropy Spike Simulation | `os.urandom()` written to 50 files (Shannon entropy ≥ 7.5 bits/byte) |
| B-03 | Process Burst Activity | 20 rapid `cmd` spawns + 1000 file I/O ops (malicious exec pattern) |
| B-04 | Registry Modification | Benign write/read/delete in `HKCU\Software\` (persistence simulation) |
| B-05 | Behavioral Consistency | Re-runs B-01/02/03 three times with variation (adaptive defense check) |

**PASS criteria:** ≥ 3 of 5 tests detected (configurable in `abae_config.json`).
**Sandbox:** `BME_TEST/` directory, fully cleaned up after run.
**No admin rights required.**

---

## Installation

```powershell
pip install -r requirements.txt
```

## Usage

1. Launch `python main.py`
2. Review detected antivirus and module list
3. Click **Start Benchmark**
4. Watch real-time console output
5. View per-test results and export to TXT

## Results Output

Each run produces a detailed TXT report under `results/` covering:
- EICAR: detection time
- GoPhish: campaign ID, click/submit counts, URL accessibility
- ATT&CK: per-technique `[DETECTED]` / `[NOT DETECTED]` table + overall count
- ABAE: per-behavioral-test table + entropy/latency/file-count metrics + PASS/FAIL verdict
- CPU avg/peak, RAM Δ, Disk read/write for every module

## Project Structure

```
Major Project/
├── main.py                    # GUI application
├── module_manager.py          # Dynamic module discovery
├── system_monitor.py          # Performance tracking
├── av_detector.py             # Antivirus detection
├── results_handler.py         # Results compilation & export
├── modules/
│   ├── base_module.py
│   ├── module_1_eicar/        # EICAR signature test
│   ├── module_2_gophish/      # GoPhish phishing simulation
│   ├── module_3_atomic/       # MITRE ATT&CK simulation
│   └── module_4_abae/         # Adaptive Behavioral Anomaly Engine
│       ├── module.py
│       ├── abae_engine.py     # All behavioral test logic
│       └── abae_config.json   # Configurable thresholds
└── results/                   # Exported TXT reports
```

## Requirements

- Python 3.11+
- Windows 10 / 11
- CustomTkinter ≥ 5.2.0
- psutil ≥ 5.9.0
- WMI ≥ 1.5.1

## Phase Status

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | GUI + EICAR | ✅ Complete |
| Phase 2 | GoPhish phishing simulation | ✅ Complete |
| Phase 3 | ATT&CK simulation (5 techniques) | ✅ Complete |
| Phase 4 | ABAE behavioral engine (5 tests) | ✅ Complete |
| Phase 5 | Database + server upload | 🔲 Planned |

## License

Educational Project — UNITAR Learn
