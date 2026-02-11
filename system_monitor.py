"""
System Monitor - Tracks CPU, RAM, and Disk I/O during module execution
"""

import psutil
import time
import threading
from typing import Dict, List, Tuple


class SystemMonitor:
    """Monitors system resources during module execution"""
    
    def __init__(self, interval: float = 0.1):
        """
        Initialize system monitor
        
        Args:
            interval: Sampling interval in seconds (default: 0.1s)
        """
        self.interval = interval
        self.monitoring = False
        self.monitor_thread = None
        
        # Metrics storage
        self.cpu_samples: List[float] = []
        self.ram_samples: List[float] = []  # In MB
        self.disk_io_start: Tuple[int, int] = (0, 0)  # (read_bytes, write_bytes)
        self.disk_io_end: Tuple[int, int] = (0, 0)
        
        # Detection tracking
        self.detection_time: float = None
        self.test_start_time: float = None
        
    def start(self):
        """Start monitoring system resources"""
        self.monitoring = True
        self.cpu_samples = []
        self.ram_samples = []
        self.test_start_time = time.time()
        
        # Get initial disk I/O
        disk_io = psutil.disk_io_counters()
        self.disk_io_start = (disk_io.read_bytes, disk_io.write_bytes)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def stop(self):
        """Stop monitoring system resources"""
        self.monitoring = False
        
        # Get final disk I/O
        disk_io = psutil.disk_io_counters()
        self.disk_io_end = (disk_io.read_bytes, disk_io.write_bytes)
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
            
    def mark_detection(self):
        """Mark the time when AV detection occurred"""
        if self.test_start_time and not self.detection_time:
            self.detection_time = time.time() - self.test_start_time
            
    def _monitor_loop(self):
        """Monitoring loop running in separate thread"""
        while self.monitoring:
            # CPU usage
            cpu = psutil.cpu_percent(interval=None)
            self.cpu_samples.append(cpu)
            
            # RAM usage in MB
            mem = psutil.virtual_memory()
            ram_mb = (mem.total - mem.available) / (1024 * 1024)
            self.ram_samples.append(ram_mb)
            
            time.sleep(self.interval)
            
    def get_results(self) -> Dict:
        """
        Get monitoring results
        
        Returns:
            Dictionary containing all metrics
        """
        # CPU metrics
        cpu_avg = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0
        cpu_peak = max(self.cpu_samples) if self.cpu_samples else 0
        
        # RAM metrics in MB
        ram_avg = sum(self.ram_samples) / len(self.ram_samples) if self.ram_samples else 0
        ram_peak = max(self.ram_samples) if self.ram_samples else 0
        
        # Disk I/O metrics in MB
        disk_read_mb = (self.disk_io_end[0] - self.disk_io_start[0]) / (1024 * 1024)
        disk_write_mb = (self.disk_io_end[1] - self.disk_io_start[1]) / (1024 * 1024)
        
        return {
            'cpu_avg': round(cpu_avg, 1),
            'cpu_peak': round(cpu_peak, 1),
            'ram_avg': round(ram_avg, 0),
            'ram_peak': round(ram_peak, 0),
            'disk_read_mb': round(disk_read_mb, 2),
            'disk_write_mb': round(disk_write_mb, 2),
            'detection_time': round(self.detection_time, 2) if self.detection_time else None
        }
        
    def reset(self):
        """Reset all metrics"""
        self.cpu_samples = []
        self.ram_samples = []
        self.disk_io_start = (0, 0)
        self.disk_io_end = (0, 0)
        self.detection_time = None
        self.test_start_time = None
