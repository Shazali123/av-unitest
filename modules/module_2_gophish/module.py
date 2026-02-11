"""
Module 2: GoPhish (Placeholder)
Generates fake results for testing purposes
"""

import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor


class GoPhishModule(BaseModule):
    """GoPhish phishing simulation module (placeholder)"""
    
    def __init__(self):
        super().__init__()
        self.name = "GoPhish Simulation"
        self.description = "Phishing awareness testing (Phase 2 - Placeholder)"
        
    def get_info(self) -> dict:
        """Get module information"""
        return {
            'id': self.module_id,
            'name': self.name,
            'description': self.description
        }
        
    def run(self, monitor: SystemMonitor) -> bool:
        """
        Placeholder execution - generates fake data
        """
        try:
            start_time = time.time()
            self.status = "Running"
            
            print(f"[GoPhish] Running placeholder test...")
            
            # Start monitoring
            monitor.start()
            
            # Simulate work for 1-2 seconds
            time.sleep(random.uniform(1.0, 2.0))
            
            # Stop monitoring
            monitor.stop()
            
            self.execution_time = time.time() - start_time
            self.metrics = monitor.get_results()
            self.status = "Completed"
            
            print(f"[GoPhish] Placeholder test completed")
            
            return True
            
        except Exception as e:
            print(f"[GoPhish] Error: {e}")
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
            'metrics': self.metrics,
            'placeholder': True
        }
