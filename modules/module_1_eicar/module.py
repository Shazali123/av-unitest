"""
Module 1: EICAR Test
Generates EICAR test file and monitors for antivirus detection
"""

import os
import time
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor


# Standard EICAR test string split across two parts to avoid triggering AV during build
_EICAR_PART1 = r'X5O!P%@AP[4\PZX54(P^)7CC)7}'
_EICAR_PART2 = r'$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
EICAR_STRING = _EICAR_PART1 + _EICAR_PART2


class EICARModule(BaseModule):
    """EICAR antivirus test module"""

    def __init__(self):
        super().__init__()
        self.name = "EICAR Test"
        self.description = "Standard antivirus detection test using EICAR test file"
        self.test_file_path = None
        self.detected = False
        self.detection_verdict = "NOT DETECTED"
        self.detection_notes = ""

    def get_info(self) -> dict:
        """Get module information"""
        return {
            'id': self.module_id,
            'name': self.name,
            'description': self.description
        }

    def _check_file_neutralised(self, path: str) -> bool:
        """
        Check if AV has neutralised the file by:
        1. File was deleted/quarantined (not exists), OR
        2. File still exists but EICAR content was wiped/replaced
        """
        if not os.path.exists(path):
            return True  # Deleted / quarantined

        # Check file content - if AV replaced content, it won't match EICAR string
        try:
            with open(path, 'r', errors='replace') as f:
                content = f.read().strip()
            if content != EICAR_STRING.strip():
                return True  # Content was neutralised
        except Exception:
            pass  # Can't read = likely quarantined/locked

        return False

    def run(self, monitor: SystemMonitor) -> bool:
        """
        Execute EICAR test

        Creates EICAR test file and monitors for AV detection
        """
        try:
            start_time = time.time()
            self.status = "Running"

            # Start monitoring
            monitor.start()

            # Create test file in temp directory
            temp_dir = os.path.join(os.path.dirname(__file__), 'temp')
            os.makedirs(temp_dir, exist_ok=True)

            self.test_file_path = os.path.join(temp_dir, 'eicar_test.txt')

            print(f"[EICAR] Creating test file at: {self.test_file_path}")

            # Write EICAR string to file
            with open(self.test_file_path, 'w') as f:
                f.write(EICAR_STRING)

            print("[EICAR] Test file created, monitoring for AV detection...")

            # Give AV a moment to process the newly created file
            time.sleep(0.2)

            # Wait and monitor for detection (max 8 seconds)
            detection_window = 8.0
            check_interval = 0.1
            elapsed = 0.0

            while elapsed < detection_window:
                if self._check_file_neutralised(self.test_file_path):
                    self.detected = True
                    self.detection_verdict = "DETECTED"
                    self.detection_notes = "AV removed or neutralised the EICAR test file"
                    monitor.mark_detection()
                    print(f"[EICAR] Detection confirmed at {round(elapsed, 2)}s "
                          f"(file removed/neutralised by AV)")
                    break

                time.sleep(check_interval)
                elapsed += check_interval

            if not self.detected:
                self.detection_verdict = "NOT DETECTED"
                self.detection_notes = (
                    "EICAR file survived full detection window. "
                    "AV may be disabled or not monitoring write activity."
                )
                print("[EICAR] No detection within time window")

            # Stop monitoring
            monitor.stop()

            # Clean up if file still exists
            if os.path.exists(self.test_file_path):
                try:
                    os.remove(self.test_file_path)
                    print("[EICAR] Test file cleaned up")
                except Exception:
                    print("[EICAR] Warning: Could not remove test file (may be quarantined)")

            self.execution_time = time.time() - start_time
            self.metrics = monitor.get_results()
            self.status = "Completed"

            return True

        except Exception as e:
            print(f"[EICAR] Error: {e}")
            self.status = "Failed"
            self.detection_verdict = "ERROR"
            self.detection_notes = str(e)
            monitor.stop()
            return False

    def get_results(self) -> dict:
        """Get test results"""
        return {
            'module_id': self.module_id,
            'name': self.name,
            'execution_time': round(self.execution_time, 2),
            'status': self.status,
            'detected': self.detected,
            'detection_verdict': self.detection_verdict,
            'detection_notes': self.detection_notes,
            'metrics': self.metrics
        }
