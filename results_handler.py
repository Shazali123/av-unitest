"""
Results Handler - Compiles and exports test results
"""

import os
from datetime import datetime
from typing import List, Dict


class ResultsHandler:
    """Handles result compilation and export"""
    
    def __init__(self, results_dir: str = "results"):
        """
        Initialize results handler
        
        Args:
            results_dir: Directory to save result files
        """
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        
    def compile_results(self, module_results: List[Dict], av_name: str) -> str:
        """
        Compile results into formatted text
        
        Args:
            module_results: List of module result dictionaries
            av_name: Detected antivirus name
            
        Returns:
            Formatted results string
        """
        output = []
        output.append("=" * 60)
        output.append("AV BENCHMARK TEST RESULTS")
        output.append("=" * 60)
        output.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Detected Antivirus: {av_name}")
        output.append("")
        output.append("-" * 60)
        output.append("MODULE RESULTS")
        output.append("-" * 60)
        
        # Calculate totals
        total_time = 0
        all_cpu_avg = []
        all_cpu_peak = []
        all_ram_avg = []
        all_ram_peak = []
        
        # Module details
        for result in module_results:
            module_id = result.get('module_id', '?')
            name = result.get('name', 'Unknown')
            exec_time = result.get('execution_time', 0)
            status = result.get('status', 'Unknown')
            metrics = result.get('metrics', {})
            
            output.append(f"\nModule {module_id} ({name}):")
            output.append(f"  Execution Time: {exec_time}s")
            
            # Detection time
            if metrics.get('detection_time'):
                output.append(f"  Detection Time: {metrics['detection_time']}s")
            else:
                output.append(f"  Detection Time: N/A")
                
            # Performance metrics
            output.append(f"  CPU Usage: Avg {metrics.get('cpu_avg', 0)}% | Peak {metrics.get('cpu_peak', 0)}%")
            output.append(f"  RAM Usage: Avg {metrics.get('ram_avg', 0)} MB | Peak {metrics.get('ram_peak', 0)} MB")
            output.append(f"  Disk I/O: Read {metrics.get('disk_read_mb', 0)} MB | Write {metrics.get('disk_write_mb', 0)} MB")
            output.append(f"  Status: {status}")
            
            # Atomic Red Team specific results
            if 'test_results' in result:
                output.append(f"\n  Test Results:")
                for test in result['test_results']:
                    status_text = "Detected" if test['detected'] else "Not Detected"
                    output.append(f"    - {test['test']}: {status_text}")
                    
            # Track totals
            total_time += exec_time
            if metrics.get('cpu_avg'):
                all_cpu_avg.append(metrics['cpu_avg'])
            if metrics.get('cpu_peak'):
                all_cpu_peak.append(metrics['cpu_peak'])
            if metrics.get('ram_avg'):
                all_ram_avg.append(metrics['ram_avg'])
            if metrics.get('ram_peak'):
                all_ram_peak.append(metrics['ram_peak'])
                
        # Summary
        output.append("")
        output.append("-" * 60)
        output.append(f"TOTAL EXECUTION TIME: {round(total_time, 2)}s")
        
        if all_cpu_avg:
            output.append(f"AVERAGE CPU USAGE: {round(sum(all_cpu_avg) / len(all_cpu_avg), 1)}%")
        if all_cpu_peak:
            output.append(f"PEAK CPU USAGE: {round(max(all_cpu_peak), 1)}%")
        if all_ram_avg:
            output.append(f"AVERAGE RAM USAGE: {round(sum(all_ram_avg) / len(all_ram_avg), 0)} MB")
        if all_ram_peak:
            output.append(f"PEAK RAM USAGE: {round(max(all_ram_peak), 0)} MB")
            
        output.append("=" * 60)
        
        return "\n".join(output)
        
    def export_to_txt(self, results_text: str) -> str:
        """
        Export results to TXT file
        
        Args:
            results_text: Formatted results string
            
        Returns:
            Path to exported file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"benchmark_results_{timestamp}.txt"
        filepath = os.path.join(self.results_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(results_text)
            
        return filepath
        
    def upload_to_server(self, results_text: str) -> bool:
        """
        Placeholder for server upload (Phase 3/4)
        
        Args:
            results_text: Formatted results string
            
        Returns:
            Always False (not implemented yet)
        """
        print("[ResultsHandler] Upload to server - Not implemented (Phase 3/4)")
        return False
