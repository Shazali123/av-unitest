# AV Benchmark Testing Framework - Phase 1

Modern GUI application for benchmarking antivirus software using multiple testing modules.

## Quick Start

```powershell
# Run the application
python main.py
```

## Features

- ✅ **GUI Interface** - Modern dark theme using CustomTkinter
- ✅ **Antivirus Detection** - Automatically detects installed AV
- ✅ **Dynamic Modules** - Add modules without code changes
- ✅ **System Monitoring** - Tracks CPU, RAM, Disk I/O
- ✅ **Results Export** - Saves detailed reports to TXT files

## Modules

### Module 1: EICAR Test (FUNCTIONAL)
Standard antivirus detection test using EICAR test file.
- Creates EICAR test file
- Monitors for AV detection
- Tracks detection time

### Module 2: GoPhish (Placeholder)
Phishing simulation module (Phase 2 development).
- Currently generates fake data for testing

### Module 3: Atomic Red Team (Placeholder)
Advanced threat simulation (Phase 2 development).
- Currently generates fake detection results
- Simulates multiple technique tests

## Installation

1. **Install Dependencies:**
```powershell
pip install -r requirements.txt
```

2. **Run Application:**
```powershell
python main.py
```

## Usage

1. Launch the application
2. Review detected antivirus and module list
3. Click "Start Benchmark"
4. Watch progress in real-time
5. View comprehensive results
6. Export to TXT file

## Results Include

- Execution time per module
- Detection time (where applicable)
- CPU usage (average & peak)
- RAM usage (average & peak)
- Disk I/O (read & write bytes)
- Overall statistics
- Individual test results (for Atomic module)

## Adding New Modules

1. Create folder: `modules/module_4_yourname/`
2. Create `__init__.py` and `module.py`
3. Inherit from `BaseModule` class
4. Implement required methods:
   - `get_info()` - Module metadata
   - `run(monitor)` - Test logic
   - `get_results()` - Results data

Module will be automatically discovered on next run!

## Project Structure

```
Major Project/
├── main.py                    # Main GUI application
├── module_manager.py          # Dynamic module discovery
├── system_monitor.py          # Performance tracking
├── av_detector.py             # Antivirus detection
├── results_handler.py         # Results compilation
├── modules/                   # Test modules directory
│   ├── base_module.py        # Base class
│   ├── module_1_eicar/       # EICAR test
│   ├── module_2_gophish/     # GoPhish (placeholder)
│   └── module_3_atomic/      # Atomic (placeholder)
└── results/                   # Exported TXT files
```

## Requirements

- Python 3.11+
- Windows 10/11
- CustomTkinter >= 5.2.0
- WMI >= 1.5.1
- psutil >= 5.9.0

## Phase 1 Status: ✅ COMPLETE

**What Works:**
- GUI with start, loading, and results screens
- Dynamic module discovery
- EICAR test (functional)
- System performance monitoring
- Results export to TXT
- Antivirus detection

**Next Steps (Phase 2):**
- Implement real GoPhish module
- Implement real Atomic Red Team tests
- Add database integration
- Prepare for server upload

## License

Educational Project - UNITAR Learn
