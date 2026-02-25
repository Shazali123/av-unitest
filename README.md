# AV Benchmark Testing Framework — Phase 3

Modern GUI application for benchmarking antivirus software using three real test modules.

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

## Modules

### Module 1: EICAR Test ✅ FUNCTIONAL
Standard antivirus detection test using the EICAR test file.
- Creates EICAR test file on disk
- Monitors for AV detection and quarantine
- Tracks detection time in seconds

### Module 2: GoPhish Phishing Simulation ✅ FUNCTIONAL
Live phishing simulation against a GoPhish server (Ubuntu VM).
- Creates real campaign via GoPhish REST API
- This Windows machine directly GETs the phishing URL (triggers SmartScreen)
- Downloads phishing page HTML to a temp `.html` file on disk (EICAR JS payload → AV file scan)
- Simulates credential POST submission
- Campaign preserved in GoPhish archive after run (no auto-delete)

Configure: `modules/module_2_gophish/gophish_config.json`

### Module 3: ATT&CK Simulation ✅ FUNCTIONAL (Phase 3)
5 live MITRE ATT&CK technique tests — no external tools required (Python stdlib only).

| # | ATT&CK ID | Technique | AV Target |
|---|-----------|-----------|-----------|
| 1 | T1059.001 | PowerShell Encoded `IEX`/`DownloadString` | AMSI / script-block logging |
| 2 | T1003.001 | LSASS dump via `comsvcs.dll` (rundll32) | Credential-dumping heuristic |
| 3 | T1218.011 | Rundll32 `javascript:` LOLBin | Living-off-the-land heuristic |
| 4 | T1105     | EICAR string downloaded to `.exe` on disk | Real-time file scanner |
| 5 | T1082     | Sysinfo recon → base64 stage → loopback exfil | Behavioural chain detection |

> **Note:** Tests 1–4 will trigger Windows Defender alerts during the run. This is the intended benchmark behaviour.

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
- Per-module execution time & status
- EICAR: detection time
- GoPhish: campaign ID, click/submit counts, phish URL accessibility
- ATT&CK: per-technique `[DETECTED]` / `[NOT DETECTED]` table + overall count
- CPU avg/peak, RAM Δ avg/peak, Disk read/write (MB) for every module

## Project Structure

```
Major Project/
├── main.py                    # Main GUI application
├── module_manager.py          # Dynamic module discovery
├── system_monitor.py          # Performance tracking
├── av_detector.py             # Antivirus detection
├── results_handler.py         # Results compilation & export
├── modules/
│   ├── base_module.py         # Abstract base class
│   ├── module_1_eicar/        # EICAR test
│   ├── module_2_gophish/      # GoPhish phishing simulation
│   └── module_3_atomic/       # ATT&CK simulation (Phase 3)
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
| Phase 4 | Database + server upload | 🔲 Planned |

## License

Educational Project — UNITAR Learn
