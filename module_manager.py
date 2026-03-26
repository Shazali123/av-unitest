# AV-Unitest — Modular Antivirus Benchmark Platform
# Copyright (c) 2026 Shazali. Licensed under GPL-3.0.
"""
Module Manager - Dynamically discovers and executes test modules
"""

import os
import importlib.util
import sys
from typing import List, Dict
from system_monitor import SystemMonitor


class ModuleManager:
    """Manages discovery and execution of test modules"""
    
    def __init__(self, modules_dir: str = "modules"):
        """
        Initialize module manager
        
        Args:
            modules_dir: Directory containing module folders
        """
        if getattr(sys, 'frozen', False):
            # Running as a bundled PyInstaller executable
            self.modules_dir = os.path.join(sys._MEIPASS, modules_dir)
        else:
            # Running as normal script
            self.modules_dir = os.path.abspath(modules_dir)
            
        # VERY IMPORTANT: When PyInstaller packages the app, base_module.py
        # exists in sys._MEIPASS/modules, NOT in external dist/AV-Unitest/modules.
        # So we must add the internal modules dir to sys.path so external
        # modules can do `from base_module import BaseModule` successfully.
        if self.modules_dir not in sys.path:
            sys.path.insert(0, self.modules_dir)
            
        self.modules: List = []
        self.results: List[Dict] = []
        self._config = self._load_config()

    def _load_config(self) -> dict:
        """
        Load modules_config.json from next to the executable (or cwd).
        Config controls which built-in modules are active.
        """
        import json
        defaults = {
            "disabled_modules": [],
            "external_modules_only": False,
        }
        # Look for config next to .exe or in cwd
        for base in [os.path.dirname(sys.executable), os.getcwd()]:
            cfg_path = os.path.join(base, 'modules_config.json')
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, 'r') as f:
                        defaults.update(json.load(f))
                    print(f"[ModuleManager] Config loaded: {cfg_path}")
                except Exception as e:
                    print(f"[ModuleManager] Config error: {e}")
                break
        return defaults

    def _scan_folder(self, folder_path: str, label: str) -> list:
        """Scan a directory for module_* subfolders."""
        found = []
        if not os.path.exists(folder_path):
            return found
        for item in os.listdir(folder_path):
            item_path = os.path.join(folder_path, item)
            if os.path.isdir(item_path) and item.startswith('module_'):
                module_py = os.path.join(item_path, 'module.py')
                if os.path.exists(module_py):
                    found.append((item, module_py, label))
        return sorted(found, key=lambda x: x[0])

    def discover_modules(self):
        """
        Dynamically discover modules from:
          1. Built-in modules/ directory (internal)
          2. External modules/ folder next to .exe (user-added)
        Respects modules_config.json for disabling/filtering.
        """
        self.modules = []
        cfg = self._config
        disabled = set(cfg.get('disabled_modules', []))
        external_only = cfg.get('external_modules_only', False)

        all_found = []

        # 1. Internal (built-in) modules
        if not external_only:
            internal = self._scan_folder(self.modules_dir, 'internal')
            for name, path, label in internal:
                if name not in disabled:
                    all_found.append((name, path, label))
                else:
                    print(f"[ModuleManager] Skipping disabled: {name}")

        # 2. External modules (next to .exe or cwd)
        for base in [os.path.dirname(sys.executable), os.getcwd()]:
            ext_dir = os.path.join(base, 'modules')
            if ext_dir != os.path.abspath(self.modules_dir):
                external = self._scan_folder(ext_dir, 'external')
                for name, path, label in external:
                    # Don't duplicate if same name as internal
                    if not any(n == name for n, _, _ in all_found):
                        all_found.append((name, path, label))

        print(f"[ModuleManager] Found {len(all_found)} module(s)")

        # Load each module
        for idx, (folder, module_path, label) in enumerate(all_found, start=1):
            try:
                spec = importlib.util.spec_from_file_location(f"{folder}.module", module_path)
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"{folder}.module"] = module
                spec.loader.exec_module(module)

                # Find the module class
                module_class = None
                for name in dir(module):
                    obj = getattr(module, name)
                    if isinstance(obj, type) and name.endswith('Module') and name != 'BaseModule':
                        module_class = obj
                        break

                if module_class:
                    module_instance = module_class()
                    module_instance.set_module_id(idx)
                    self.modules.append(module_instance)
                    print(f"[ModuleManager] Loaded [{label}]: {folder} (ID: {idx})")
                else:
                    print(f"[ModuleManager] Warning: No module class found in {folder}")

            except Exception as e:
                print(f"[ModuleManager] Error loading {folder}: {e}")

        print(f"[ModuleManager] Successfully loaded {len(self.modules)} module(s)")
        
    def run_modules(self, progress_callback=None) -> List[Dict]:
        """
        Execute all modules sequentially
        
        Args:
            progress_callback: Optional callback function(current, total, module_name)
            
        Returns:
            List of module results
        """
        self.results = []
        total_modules = len(self.modules)
        
        print(f"\n[ModuleManager] Starting execution of {total_modules} modules...")
        print("=" * 60)
        
        for idx, module in enumerate(self.modules, start=1):
            module_info = module.get_info()
            print(f"\n[{idx}/{total_modules}] Running: {module_info['name']}")
            
            if progress_callback:
                progress_callback(idx, total_modules, module_info['name'])
                
            # Create monitor for this module
            monitor = SystemMonitor()
            
            # Run module
            success = module.run(monitor)
            
            # Get results
            results = module.get_results()
            self.results.append(results)
            
            status = "✓" if success else "✗"
            print(f"[{idx}/{total_modules}] {status} {module_info['name']}: {results['status']}")
            
        print("=" * 60)
        print(f"[ModuleManager] All modules completed\n")
        
        return self.results
        
    def get_module_count(self) -> int:
        """Get number of discovered modules"""
        return len(self.modules)
        
    def get_module_list(self) -> List[Dict]:
        """Get list of module information"""
        return [m.get_info() for m in self.modules]
