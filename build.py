# AV-Unitest — Modular Antivirus Benchmark Platform
# Copyright (c) 2026 Shazali. Licensed under GPL-3.0.
"""
Build script — packages AV-Unitest into a standalone .exe using PyInstaller.

Usage:
    python build.py

Output:
    dist/AV-Unitest.exe
"""

import os
import sys
import subprocess


def get_resource_path(relative_path):
    """Resolve path for bundled resources (works in both dev and frozen .exe)."""
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(__file__), relative_path)


def build():
    """Run PyInstaller to create AV-Unitest.exe."""
    print("=" * 50)
    print("  AV-Unitest Build Script")
    print("=" * 50)

    # Ensure PyInstaller is installed
    try:
        import PyInstaller
        print(f"[BUILD] PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("[BUILD] PyInstaller not found — installing...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])

    # Collect all data files to bundle
    datas = [
        # Module files
        ('modules', 'modules'),
        # License
        ('LICENSE', '.'),
        # README
        ('README.txt', '.'),
    ]

    # Build data args
    data_args = []
    for src, dst in datas:
        if os.path.exists(src):
            data_args.extend(['--add-data', f'{src}{os.pathsep}{dst}'])
            print(f"[BUILD] Bundling: {src} → {dst}")
        else:
            print(f"[BUILD] Warning: {src} not found, skipping")

    # Hidden imports that PyInstaller might miss
    hidden = [
        '--hidden-import', 'wmi',
        '--hidden-import', 'psutil',
        '--hidden-import', 'customtkinter',
    ]

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',
        '--windowed',
        '--name', 'AV-Unitest',
        '--icon', 'NONE',
        *data_args,
        *hidden,
        '--clean',
        'main.py'
    ]

    print(f"\n[BUILD] Command: {' '.join(cmd)}\n")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        exe_path = os.path.join('dist', 'AV-Unitest.exe')
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"\n[BUILD] ✓ SUCCESS: {exe_path} ({size_mb:.1f} MB)")
        else:
            print("\n[BUILD] ✓ Build completed (check dist/ folder)")
    else:
        print(f"\n[BUILD] ✗ Build failed with exit code {result.returncode}")
        sys.exit(1)


if __name__ == '__main__':
    build()
