"""
Module 2: GoPhish Simulation (Phase 2)
Connects to a GoPhish HQ server via REST API to run phishing simulation
and collect awareness/detection metrics.

Config: modules/module_2_gophish/gophish_config.json
"""

import os
import sys
import json
import time
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor

# Optional import - only needed for live mode
try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


# ---------------------------------------------------------------------------
# Tiny GoPhish REST client (no third-party dependencies required)
# ---------------------------------------------------------------------------

class GoPhishClient:
    """Minimal GoPhish REST API client using only stdlib urllib"""

    def __init__(self, host: str, api_key: str):
        self.host = host.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Content-Type': 'application/json',
        }

    def _request(self, method: str, path: str, data: dict = None):
        """
        Make an API request.
        Returns (status_code, response_dict).
        Raises urllib.error.URLError on network failure.
        """
        import urllib.request
        import urllib.error
        import ssl

        url = f"{self.host}/api{path}?api_key={self.api_key}"

        body = json.dumps(data).encode('utf-8') if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header('Content-Type', 'application/json')

        # Allow self-signed certs on internal VMs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read().decode('utf-8')
            return resp.status, json.loads(raw) if raw else {}

    # --- Campaigns ---

    def get_campaigns(self):
        _, data = self._request('GET', '/campaigns/')
        return data  # list

    def create_campaign(self, payload: dict):
        _, data = self._request('POST', '/campaigns/', data=payload)
        return data  # campaign dict with 'id'

    def get_campaign_results(self, campaign_id: int):
        _, data = self._request('GET', f'/campaigns/{campaign_id}/results')
        return data

    def complete_campaign(self, campaign_id: int):
        try:
            self._request('GET', f'/campaigns/{campaign_id}/complete')
        except Exception:
            pass  # Best-effort cleanup

    # --- SMTP Profiles ---

    def get_smtp_profiles(self):
        _, data = self._request('GET', '/smtp/')
        return data

    # --- Templates ---

    def get_templates(self):
        _, data = self._request('GET', '/templates/')
        return data

    # --- Landing Pages ---

    def get_pages(self):
        _, data = self._request('GET', '/pages/')
        return data

    # --- User Groups ---

    def get_groups(self):
        _, data = self._request('GET', '/groups/')
        return data

    def create_group(self, name: str, targets: list):
        """Create a temporary target group"""
        payload = {
            'name': name,
            'targets': targets
        }
        _, data = self._request('POST', '/groups/', data=payload)
        return data

    def delete_group(self, group_id: int):
        try:
            self._request('DELETE', f'/groups/{group_id}')
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helper to lookup resource by name
# ---------------------------------------------------------------------------

def _find_by_name(items: list, name: str):
    """Find a resource dict in a list by its 'name' field (case-insensitive)"""
    name_lower = name.lower()
    for item in items:
        if isinstance(item, dict) and item.get('name', '').lower() == name_lower:
            return item
    return None


# ---------------------------------------------------------------------------
# Result counter from GoPhish campaign events
# ---------------------------------------------------------------------------

def _count_results(results_data: dict):
    """
    Parse GoPhish campaign results into counters.
    GoPhish result statuses:
      'Email Sent', 'Email Opened', 'Clicked Link',
      'Submitted Data', 'Email Reported'
    """
    sent = 0
    opened = 0
    clicked = 0
    submitted = 0
    reported = 0  # Reported as phishing (user flagged it)

    for r in results_data.get('results', []):
        status = r.get('status', '')
        if status in ('Email Sent', 'Email Opened', 'Clicked Link',
                      'Submitted Data', 'Email Reported'):
            sent += 1
        if status in ('Email Opened', 'Clicked Link',
                      'Submitted Data', 'Email Reported'):
            opened += 1
        if status in ('Clicked Link', 'Submitted Data'):
            clicked += 1
        if status == 'Submitted Data':
            submitted += 1
        if status == 'Email Reported':
            reported += 1

    return sent, opened, clicked, submitted, reported


# ---------------------------------------------------------------------------
# The Module
# ---------------------------------------------------------------------------

class GoPhishModule(BaseModule):
    """GoPhish phishing simulation module - Phase 2"""

    def __init__(self):
        super().__init__()
        self.name = "GoPhish Simulation"
        self.description = "Phishing email awareness & detection testing via GoPhish API"
        self.detected = False
        self.gophish_results = {}
        self.offline_demo = False
        self._config = self._load_config()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self) -> dict:
        config_path = os.path.join(os.path.dirname(__file__), 'gophish_config.json')
        defaults = {
            "host": "http://127.0.0.1:3333",
            "api_key": "",
            "campaign_name": "AV_Benchmark_Test",
            "smtp_profile": "",
            "email_template": "",
            "landing_page": "",
            "target_email": "test@example.local",
            "target_first_name": "Test",
            "target_last_name": "Target",
            "poll_duration_seconds": 60,
            "offline_demo_mode": False
        }
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded = json.load(f)
                defaults.update(loaded)
            except Exception as e:
                print(f"[GoPhish] Could not load config: {e}")
        return defaults

    def get_info(self) -> dict:
        return {
            'id': self.module_id,
            'name': self.name,
            'description': self.description
        }

    # ------------------------------------------------------------------
    # Offline demo mode
    # ------------------------------------------------------------------

    def _run_offline_demo(self, monitor: SystemMonitor, start_time: float):
        """Return plausible demo results when server is unreachable"""
        import random
        print("[GoPhish] Running in OFFLINE DEMO mode")
        time.sleep(2)  # Simulate some work
        monitor.stop()

        self.offline_demo = True
        self.detected = False  # Demo: email wasn't flagged

        self.gophish_results = {
            'campaign_id': 'DEMO',
            'campaign_status': 'Completed (Demo)',
            'emails_sent': 5,
            'emails_opened': random.randint(1, 4),
            'links_clicked': random.randint(0, 2),
            'credentials_submitted': random.randint(0, 1),
            'emails_flagged_spam': 0,
        }
        self.execution_time = time.time() - start_time
        self.metrics = monitor.get_results()
        self.status = "Completed (Demo)"

    # ------------------------------------------------------------------
    # Live GoPhish run
    # ------------------------------------------------------------------

    def _run_live(self, monitor: SystemMonitor, start_time: float) -> bool:
        cfg = self._config
        client = GoPhishClient(cfg['host'], cfg['api_key'])

        print(f"[GoPhish] Connecting to {cfg['host']} ...")

        # ---- Resolve resources ----
        try:
            smtp_list  = client.get_smtp_profiles()
            tpl_list   = client.get_templates()
            page_list  = client.get_pages()
        except Exception as e:
            print(f"[GoPhish] ERROR connecting to server: {e}")
            return False

        smtp  = _find_by_name(smtp_list,  cfg['smtp_profile'])
        tpl   = _find_by_name(tpl_list,   cfg['email_template'])
        page  = _find_by_name(page_list,  cfg['landing_page'])

        missing = []
        if not smtp:
            missing.append(f"SMTP profile '{cfg['smtp_profile']}'")
        if not tpl:
            missing.append(f"Email template '{cfg['email_template']}'")
        if not page:
            missing.append(f"Landing page '{cfg['landing_page']}'")

        if missing:
            print(f"[GoPhish] Missing GoPhish resources: {', '.join(missing)}")
            print("[GoPhish] Please create them in the GoPhish web UI first.")
            return False

        # ---- Create temporary target group ----
        group_name = f"BenchMark_Group_{int(time.time())}"
        target = {
            'first_name': cfg.get('target_first_name', 'Test'),
            'last_name':  cfg.get('target_last_name', 'Target'),
            'email':      cfg['target_email'],
            'position':   'Benchmark Target',
        }
        print(f"[GoPhish] Creating target group: {group_name}")
        group_data = client.create_group(group_name, [target])
        group_id = group_data.get('id')

        if not group_id:
            print("[GoPhish] Failed to create target group")
            return False

        # ---- Create campaign ----
        launch_time = (datetime.datetime.utcnow() +
                       datetime.timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%S+00:00')

        campaign_payload = {
            'name':           cfg['campaign_name'],
            'template':       {'name': tpl['name']},
            'landing_page':   {'name': page['name']},
            'smtp':           {'name': smtp['name']},
            'launch_date':    launch_time,
            'groups':         [{'name': group_name}],
        }

        print("[GoPhish] Creating campaign...")
        campaign_data = client.create_campaign(campaign_payload)
        campaign_id = campaign_data.get('id')

        if not campaign_id:
            print("[GoPhish] Failed to create campaign")
            client.delete_group(group_id)
            return False

        print(f"[GoPhish] Campaign created (ID: {campaign_id}). "
              f"Polling for {cfg['poll_duration_seconds']}s ...")

        # ---- Poll results ----
        poll_secs = int(cfg.get('poll_duration_seconds', 60))
        poll_interval = 5
        elapsed = 0

        sent = opened = clicked = submitted = flagged = 0

        while elapsed < poll_secs:
            time.sleep(poll_interval)
            elapsed += poll_interval

            try:
                results_data = client.get_campaign_results(campaign_id)
                sent, opened, clicked, submitted, flagged = _count_results(results_data)
                campaign_status = results_data.get('status', 'Unknown')
                print(f"[GoPhish] Poll {elapsed}s | Sent:{sent} "
                      f"Opened:{opened} Clicked:{clicked} "
                      f"Submitted:{submitted} Flagged:{flagged}")
            except Exception as e:
                print(f"[GoPhish] Poll error: {e}")

        # ---- Complete campaign (clean up) ----
        client.complete_campaign(campaign_id)
        client.delete_group(group_id)

        # Detection: if zero emails were opened and at least one was sent,
        # the email was likely blocked or flagged by email security
        self.detected = (sent > 0 and opened == 0 and flagged > 0)

        self.gophish_results = {
            'campaign_id':            campaign_id,
            'campaign_status':        campaign_status if 'campaign_status' in dir() else 'Completed',
            'emails_sent':            sent,
            'emails_opened':          opened,
            'links_clicked':          clicked,
            'credentials_submitted':  submitted,
            'emails_flagged_spam':    flagged,
        }

        monitor.stop()
        self.execution_time = time.time() - start_time
        self.metrics = monitor.get_results()
        self.status = "Completed"

        return True

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, monitor: SystemMonitor) -> bool:
        try:
            start_time = time.time()
            self.status = "Running"
            monitor.start()

            cfg = self._config
            use_demo = (
                cfg.get('offline_demo_mode', False)
                or not cfg.get('api_key', '').strip()
                or cfg.get('api_key', '') == 'YOUR_API_KEY_HERE'
            )

            if use_demo:
                self._run_offline_demo(monitor, start_time)
                return True
            else:
                ok = self._run_live(monitor, start_time)
                if not ok:
                    print("[GoPhish] Live run failed, falling back to demo mode")
                    self._run_offline_demo(monitor, start_time)
                return True

        except Exception as e:
            print(f"[GoPhish] Unexpected error: {e}")
            self.status = "Failed"
            monitor.stop()
            self.execution_time = time.time() - start_time
            self.metrics = monitor.get_results()
            return False

    def get_results(self) -> dict:
        """Get test results"""
        return {
            'module_id':       self.module_id,
            'name':            self.name,
            'execution_time':  round(self.execution_time, 2),
            'status':          self.status,
            'detected':        self.detected,
            'offline_demo':    self.offline_demo,
            'gophish_results': self.gophish_results,
            'metrics':         self.metrics,
        }
