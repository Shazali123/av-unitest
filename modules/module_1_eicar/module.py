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


class EICARModule(BaseModule):
    """EICAR antivirus test module"""
    
    def __init__(self):
        super().__init__()
        self.name = "EICAR Test"
        self.description = "Standard antivirus detection test using EICAR test file"
        self.test_file_path = None
        self.detected = False
        
    def get_info(self) -> dict:
        """Get module information"""
        return {
            'id': self.module_id,
            'name': self.name,
            'description': self.description
        }
        
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
            
            # EICAR test string (standard antivirus test file)
            eicar_string = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            
            # Create test file in temp directory
            temp_dir = os.path.join(os.path.dirname(__file__), 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            
            self.test_file_path = os.path.join(temp_dir, 'eicar_test.txt')
            
            print(f"[EICAR] Creating test file at: {self.test_file_path}")
            
            # Write EICAR string to file
            with open(self.test_file_path, 'w') as f:
                f.write(eicar_string)
                
            print("[EICAR] Test file created, waiting for AV detection...")
            
            # Wait and monitor for detection (max 5 seconds)
            detection_window = 5.0
            check_interval = 0.1
            elapsed = 0
            
            while elapsed < detection_window:
                if not os.path.exists(self.test_file_path):
                    # File was quarantined/deleted by AV
                    self.detected = True
                    monitor.mark_detection()
                    print(f"[EICAR] Detection confirmed! File removed by AV")
                    break
                    
                time.sleep(check_interval)
                elapsed += check_interval
                
            # Stop monitoring
            monitor.stop()
            
            # Clean up if file still exists
            if os.path.exists(self.test_file_path):
                try:
                    os.remove(self.test_file_path)
                    print("[EICAR] Test file cleaned up")
                except:
                    print("[EICAR] Warning: Could not remove test file (may be quarantined)")
                    
            self.execution_time = time.time() - start_time
            self.metrics = monitor.get_results()
            self.status = "Completed"
            
            return True
            
        except Exception as e:
            print(f"[EICAR] Error: {e}")
            self.status = "Failed"
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
            'metrics': self.metrics
        }
