"""
Results Handler - Compiles and exports test results
"""

import os
from datetime import datetime
from typing import List, Dict


class ResultsHandler:
    """Handles result compilation and export"""

    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_line(detected: bool) -> str:
        if detected:
            return "  >>> VERDICT: [DETECTED] <<<"
        return "  >>> VERDICT: [NOT DETECTED] <<<"

    @staticmethod
    def _fmt_ram(mb: float) -> str:
        """Format RAM delta value nicely"""
        if mb < 1.0:
            return f"{round(mb * 1024, 1)} KB"
        return f"{round(mb, 2)} MB"

    # ------------------------------------------------------------------
    # EICAR section
    # ------------------------------------------------------------------

    def _format_eicar(self, result: dict, metrics: dict) -> List[str]:
        lines = []
        detected = result.get('detected', False)
        verdict = result.get('detection_verdict', 'UNKNOWN')
        notes = result.get('detection_notes', '')
        det_time = metrics.get('detection_time')

        lines.append(self._verdict_line(detected))

        if det_time is not None:
            lines.append(f"  Detection Time  : {det_time}s after file creation")
        else:
            lines.append("  Detection Time  : N/A (no detection within test window)")

        if notes:
            lines.append(f"  Notes           : {notes}")

        return lines

    # ------------------------------------------------------------------
    # GoPhish section
    # ------------------------------------------------------------------

    def _format_gophish(self, result: dict) -> List[str]:
        lines = []
        gp = result.get('gophish_results', {})
        offline = result.get('offline_demo', False)

        if offline:
            lines.append("  [OFFLINE DEMO MODE - GoPhish server not configured]")

        emails_sent     = gp.get('emails_sent', 'N/A')
        emails_opened   = gp.get('emails_opened', 'N/A')
        links_clicked   = gp.get('links_clicked', 'N/A')
        creds_submitted = gp.get('credentials_submitted', 'N/A')
        emails_flagged  = gp.get('emails_flagged_spam', 'N/A')
        campaign_id     = gp.get('campaign_id', 'N/A')
        campaign_status = gp.get('campaign_status', 'N/A')
        detected        = result.get('detected', False)

        lines.append(self._verdict_line(detected))
        lines.append(f"  Campaign ID     : {campaign_id}")
        lines.append(f"  Campaign Status : {campaign_status}")
        lines.append(f"  Emails Sent     : {emails_sent}")
        lines.append(f"  Emails Opened   : {emails_opened}")
        lines.append(f"  Links Clicked   : {links_clicked}")
        lines.append(f"  Creds Submitted : {creds_submitted}")
        lines.append(f"  Flagged as Spam : {emails_flagged}")

        if isinstance(emails_sent, int) and emails_sent > 0:
            if isinstance(emails_opened, int):
                open_rate = round(emails_opened / emails_sent * 100, 1)
                lines.append(f"  Open Rate       : {open_rate}%")
            if isinstance(links_clicked, int):
                click_rate = round(links_clicked / emails_sent * 100, 1)
                lines.append(f"  Click Rate      : {click_rate}%")

        return lines

    # ------------------------------------------------------------------
    # Main compile
    # ------------------------------------------------------------------

    def compile_results(self, module_results: List[Dict], av_name: str) -> str:
        output = []
        output.append("=" * 62)
        output.append("  AV BENCHMARK TEST RESULTS")
        output.append("=" * 62)
        output.append(f"  Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"  AV       : {av_name}")
        output.append("")
        output.append("-" * 62)
        output.append("  MODULE RESULTS")
        output.append("-" * 62)

        total_time = 0.0
        all_cpu_avg = []
        all_cpu_peak = []
        all_ram_avg = []
        all_ram_peak = []

        for result in module_results:
            module_id  = result.get('module_id', '?')
            name       = result.get('name', 'Unknown')
            exec_time  = result.get('execution_time', 0)
            status     = result.get('status', 'Unknown')
            metrics    = result.get('metrics', {})

            output.append("")
            output.append(f"  Module {module_id}: {name}")
            output.append(f"  {'─' * 56}")
            output.append(f"  Execution Time  : {exec_time}s")
            output.append(f"  Status          : {status}")

            # --- Module-specific sections ---
            if name == "EICAR Test":
                output.extend(self._format_eicar(result, metrics))

            elif name == "GoPhish Simulation":
                output.extend(self._format_gophish(result))

            # Generic test_results block (Atomic etc.)
            if 'test_results' in result:
                output.append("  Individual Test Results:")
                for test in result['test_results']:
                    status_text = "[DETECTED]" if test['detected'] else "[NOT DETECTED]"
                    output.append(f"    - {test['test']}: {status_text}")

            # --- Performance metrics ---
            output.append("")
            output.append("  System Performance During Test:")
            output.append(f"    CPU    : Avg {metrics.get('cpu_avg', 0)}%  |  Peak {metrics.get('cpu_peak', 0)}%")

            ram_avg_val  = metrics.get('ram_avg', 0)
            ram_peak_val = metrics.get('ram_peak', 0)
            output.append(f"    RAM Δ  : Avg {self._fmt_ram(ram_avg_val)}  |  Peak {self._fmt_ram(ram_peak_val)}")
            output.append(f"    Disk   : Read {metrics.get('disk_read_mb', 0)} MB  |  Write {metrics.get('disk_write_mb', 0)} MB")

            # Accumulate summary totals
            total_time += exec_time
            if metrics.get('cpu_avg'):
                all_cpu_avg.append(metrics['cpu_avg'])
            if metrics.get('cpu_peak'):
                all_cpu_peak.append(metrics['cpu_peak'])
            if metrics.get('ram_avg') is not None:
                all_ram_avg.append(metrics['ram_avg'])
            if metrics.get('ram_peak') is not None:
                all_ram_peak.append(metrics['ram_peak'])

        # --- Summary ---
        output.append("")
        output.append("=" * 62)
        output.append("  SUMMARY")
        output.append("-" * 62)
        output.append(f"  Total Execution Time : {round(total_time, 2)}s")

        if all_cpu_avg:
            output.append(f"  Avg CPU Usage        : {round(sum(all_cpu_avg) / len(all_cpu_avg), 1)}%")
        if all_cpu_peak:
            output.append(f"  Peak CPU Usage       : {round(max(all_cpu_peak), 1)}%")
        if all_ram_avg:
            avg_r = round(sum(all_ram_avg) / len(all_ram_avg), 2)
            output.append(f"  Avg RAM Δ            : {self._fmt_ram(avg_r)}")
        if all_ram_peak:
            peak_r = round(max(all_ram_peak), 2)
            output.append(f"  Peak RAM Δ           : {self._fmt_ram(peak_r)}")

        output.append("=" * 62)

        return "\n".join(output)

    # ------------------------------------------------------------------

    def export_to_txt(self, results_text: str) -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename  = f"benchmark_results_{timestamp}.txt"
        filepath  = os.path.join(self.results_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(results_text)

        return filepath

    def upload_to_server(self, results_text: str) -> bool:
        """Placeholder for server upload (Phase 3/4)"""
        print("[ResultsHandler] Upload to server - Not implemented (Phase 3/4)")
        return False
