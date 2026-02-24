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
import ssl
import urllib.request
import urllib.error
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from base_module import BaseModule
from system_monitor import SystemMonitor


# ---------------------------------------------------------------------------
# Tiny GoPhish REST client
# ---------------------------------------------------------------------------

class GoPhishClient:
    """Minimal GoPhish REST API client (stdlib only)"""

    def __init__(self, host: str, api_key: str, timeout: int = 15):
        self.host    = host.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self._ctx    = self._make_ssl_ctx()

    @staticmethod
    def _make_ssl_ctx():
        """SSL context that accepts self-signed certs (internal VMs)"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, data: dict = None):
        """
        Make API request, return (status_code, parsed_body).
        Raises on network errors; returns (error_code, {}) on HTTP errors.
        """
        url  = f"{self.host}/api{path}?api_key={self.api_key}"
        body = json.dumps(data).encode('utf-8') if data else None
        req  = urllib.request.Request(url, data=body, method=method)
        req.add_header('Content-Type', 'application/json')

        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ctx) as resp:
                raw = resp.read().decode('utf-8')
                return resp.status, (json.loads(raw) if raw.strip() else {})

        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')
            print(f"  [GoPhish API] HTTP {e.code} on {method} {path}: {err_body[:300]}")
            return e.code, {}

    def _get_list(self, path: str) -> list:
        """
        GET a resource list endpoint.
        Handles both plain-list responses and wrapped {"data": [...]} responses.
        """
        code, data = self._request('GET', path)
        if code != 200:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Newer GoPhish builds wrap in {"data": [...]}
            for key in ('data', 'results', 'items'):
                if isinstance(data.get(key), list):
                    return data[key]
        return []

    # ---- Public methods ----

    def get_smtp_profiles(self) -> list:
        return self._get_list('/smtp/')

    def get_templates(self) -> list:
        return self._get_list('/templates/')

    def get_pages(self) -> list:
        return self._get_list('/pages/')

    def create_group(self, name: str, targets: list) -> dict:
        code, data = self._request('POST', '/groups/', data={
            'name':    name,
            'targets': targets,
        })
        if code not in (200, 201):
            print(f"  [GoPhish API] create_group failed (HTTP {code})")
            return {}
        return data if isinstance(data, dict) else {}

    def delete_group(self, group_id):
        try:
            self._request('DELETE', f'/groups/{group_id}')
        except Exception:
            pass

    def create_campaign(self, payload: dict) -> dict:
        code, data = self._request('POST', '/campaigns/', data=payload)
        if code not in (200, 201):
            print(f"  [GoPhish API] create_campaign failed (HTTP {code})")
            return {}
        return data if isinstance(data, dict) else {}

    def get_campaign_results(self, campaign_id) -> dict:
        code, data = self._request('GET', f'/campaigns/{campaign_id}/results')
        if code != 200:
            return {}
        return data if isinstance(data, dict) else {}

    def complete_campaign(self, campaign_id):
        try:
            self._request('GET', f'/campaigns/{campaign_id}/complete')
        except Exception:
            pass

    def ping(self) -> bool:
        """Return True if we can reach the API with a valid key"""
        try:
            code, _ = self._request('GET', '/campaigns/')
            return code == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_by_name(items: list, name: str):
    """Case-insensitive name lookup in a list of resource dicts"""
    name_lower = name.lower().strip()
    for item in items:
        if isinstance(item, dict):
            if item.get('name', '').lower().strip() == name_lower:
                return item
    return None


def _count_results(results_data: dict):
    """
    Parse GoPhish campaign results into counters.
    GoPhish result statuses (current):
      'Email Sent', 'Email Opened', 'Clicked Link',
      'Submitted Data', 'Email Reported'
    """
    sent = opened = clicked = submitted = reported = 0
    for r in results_data.get('results', []):
        status = r.get('status', '')
        # Every result entry represents one target
        if status in ('Email Sent', 'Email Opened',
                      'Clicked Link', 'Submitted Data', 'Email Reported'):
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
        self.name            = "GoPhish Simulation"
        self.description     = "Phishing email awareness & detection testing via GoPhish API"
        self.detected        = False
        self.gophish_results = {}
        self.offline_demo    = False
        self._config         = self._load_config()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self) -> dict:
        # Use abspath so this works when loaded dynamically via importlib
        # (relative __file__ would break if cwd != tool root)
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'gophish_config.json'
        )
        defaults = {
            "host":                  "http://127.0.0.1:3333",
            "api_key":               "",
            "campaign_name":         "AV_Benchmark_Test",
            "smtp_profile":          "",
            "email_template":        "",
            "landing_page":          "",
            "target_email":          "test@example.local",
            "target_first_name":     "Test",
            "target_last_name":      "Target",
            "poll_duration_seconds": 60,
            "offline_demo_mode":     False,
        }
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded = json.load(f)
                defaults.update(loaded)
                print(f"[GoPhish] Config loaded: {config_path}")
                print(f"[GoPhish] Host: {defaults['host']}  "
                      f"| offline_demo: {defaults['offline_demo_mode']}  "
                      f"| api_key set: {bool(defaults['api_key'].strip())}")
            except Exception as e:
                print(f"[GoPhish] Could not load config ({config_path}): {e}")
        else:
            print(f"[GoPhish] WARNING: config file NOT found at: {config_path}")
            print("[GoPhish] Falling back to defaults (demo mode likely)")
        return defaults

    def get_info(self) -> dict:
        return {
            'id':          self.module_id,
            'name':        self.name,
            'description': self.description,
        }

    # ------------------------------------------------------------------
    # Offline demo mode
    # ------------------------------------------------------------------

    def _run_offline_demo(self, monitor: SystemMonitor, start_time: float,
                          reason: str = ""):
        """Return plausible demo results without hitting the server"""
        import random
        msg = f"[GoPhish] OFFLINE DEMO MODE" + (f" ({reason})" if reason else "")
        print(msg)
        time.sleep(2)
        monitor.stop()

        self.offline_demo    = True
        self.detected        = False

        self.gophish_results = {
            'campaign_id':           'DEMO',
            'campaign_status':       'Completed (Demo)',
            'emails_sent':           5,
            'emails_opened':         random.randint(1, 4),
            'links_clicked':         random.randint(0, 2),
            'credentials_submitted': random.randint(0, 1),
            'emails_flagged_spam':   0,
        }
        self.execution_time = time.time() - start_time
        self.metrics        = monitor.get_results()
        self.status         = "Completed (Demo)"

    # ------------------------------------------------------------------
    # Live GoPhish run
    # ------------------------------------------------------------------

    def _run_live(self, monitor: SystemMonitor, start_time: float) -> bool:
        cfg    = self._config
        client = GoPhishClient(cfg['host'], cfg['api_key'])

        print(f"[GoPhish] Connecting to {cfg['host']} ...")

        # ---- Connectivity check ----
        if not client.ping():
            print(f"[GoPhish] Cannot reach server at {cfg['host']}")
            return False
        print("[GoPhish] Connected OK")

        # ---- Resolve resources ----
        smtp_list = client.get_smtp_profiles()
        tpl_list  = client.get_templates()
        page_list = client.get_pages()

        print(f"[GoPhish] Found {len(smtp_list)} SMTP profile(s), "
              f"{len(tpl_list)} template(s), {len(page_list)} landing page(s)")

        smtp = _find_by_name(smtp_list, cfg['smtp_profile'])
        tpl  = _find_by_name(tpl_list,  cfg['email_template'])
        page = _find_by_name(page_list, cfg['landing_page'])

        missing = []
        if not smtp:
            names = [s.get('name') for s in smtp_list]
            missing.append(
                f"SMTP '{cfg['smtp_profile']}' (available: {names})"
            )
        if not tpl:
            names = [t.get('name') for t in tpl_list]
            missing.append(
                f"Template '{cfg['email_template']}' (available: {names})"
            )
        if not page:
            names = [p.get('name') for p in page_list]
            missing.append(
                f"Landing page '{cfg['landing_page']}' (available: {names})"
            )

        if missing:
            print("[GoPhish] Missing resources - cannot create campaign:")
            for m in missing:
                print(f"  - {m}")
            return False

        # ---- Create temporary target group ----
        group_name = f"BM_Group_{int(time.time())}"
        target = {
            'first_name': cfg.get('target_first_name', 'Test'),
            'last_name':  cfg.get('target_last_name',  'Target'),
            'email':      cfg['target_email'],
            'position':   'Benchmark Target',
        }
        print(f"[GoPhish] Creating group '{group_name}'...")
        group_data = client.create_group(group_name, [target])
        group_id   = group_data.get('id')

        if not group_id:
            print("[GoPhish] Failed to create target group")
            return False

        # ---- Create campaign ----
        launch_dt   = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)
        launch_time = launch_dt.strftime('%Y-%m-%dT%H:%M:%S+00:00')

        # Build phish server URL from config host IP + phish_port (default 8081)
        try:
            host_ip   = cfg['host'].split('://')[-1].split(':')[0]
            phish_url = f"http://{host_ip}:{cfg.get('phish_port', 8081)}"
        except Exception:
            phish_url = cfg['host']
        print(f"[GoPhish] Phish URL: {phish_url}")

        # GoPhish API uses 'page' (NOT 'landing_page') for the landing page ref
        campaign_payload = {
            'name':        cfg['campaign_name'],
            'template':    {'name': tpl['name']},
            'page':        {'name': page['name']},
            'smtp':        {'name': smtp['name']},
            'launch_date': launch_time,
            'url':         phish_url,
            'groups':      [{'name': group_name}],
        }

        print("[GoPhish] Creating campaign...")
        campaign_data = client.create_campaign(campaign_payload)
        campaign_id   = campaign_data.get('id')

        if not campaign_id:
            print(f"[GoPhish] create_campaign returned: {campaign_data}")
            client.delete_group(group_id)
            return False

        print(f"[GoPhish] Campaign ID={campaign_id}. "
              f"Polling for {cfg['poll_duration_seconds']}s ...")

        # ---- Poll results ----
        poll_secs      = int(cfg.get('poll_duration_seconds', 60))
        poll_interval  = 5
        elapsed        = 0
        campaign_status = 'Unknown'
        sent = opened = clicked = submitted = flagged = 0

        while elapsed < poll_secs:
            time.sleep(poll_interval)
            elapsed += poll_interval

            try:
                results_data    = client.get_campaign_results(campaign_id)
                campaign_status = results_data.get('status', campaign_status)
                sent, opened, clicked, submitted, flagged = \
                    _count_results(results_data)
                print(f"  [Poll {elapsed:3d}s] Sent:{sent} "
                      f"Opened:{opened} Clicked:{clicked} "
                      f"Submitted:{submitted} Flagged:{flagged} "
                      f"Status:{campaign_status}")
            except Exception as e:
                print(f"  [Poll {elapsed:3d}s] Error: {e}")

        # ---- Finalise ----
        client.complete_campaign(campaign_id)
        client.delete_group(group_id)

        # Detection logic: email was blocked if it was sent but never opened
        # AND email was reported as phishing/spam
        self.detected = (sent > 0 and opened == 0 and flagged > 0)

        self.gophish_results = {
            'campaign_id':           campaign_id,
            'campaign_status':       campaign_status,
            'emails_sent':           sent,
            'emails_opened':         opened,
            'links_clicked':         clicked,
            'credentials_submitted': submitted,
            'emails_flagged_spam':   flagged,
        }

        monitor.stop()
        self.execution_time = time.time() - start_time
        self.metrics        = monitor.get_results()
        self.status         = "Completed"
        return True

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, monitor: SystemMonitor) -> bool:
        start_time = time.time()
        try:
            self.status = "Running"
            monitor.start()

            cfg = self._config
            use_demo = (
                cfg.get('offline_demo_mode', False)
                or not cfg.get('api_key', '').strip()
                or cfg.get('api_key', '') == 'YOUR_API_KEY_HERE'
            )

            if use_demo:
                self._run_offline_demo(monitor, start_time,
                                       reason="offline_demo_mode=true or no API key")
                return True

            # --- Try live ---
            try:
                ok = self._run_live(monitor, start_time)
            except Exception as live_err:
                print(f"[GoPhish] Live error: {live_err}")
                ok = False

            if not ok:
                # Fallback to demo so results are still usable
                print("[GoPhish] Falling back to OFFLINE DEMO mode")
                # Monitor may already be stopped if _run_live stopped it partway
                if monitor.monitoring:
                    monitor.stop()
                # Re-start a fresh monitor for demo timing
                monitor2 = type(monitor)()
                monitor2.start()
                self._run_offline_demo(monitor2, start_time,
                                       reason="server unreachable or config issue")
            return True

        except Exception as e:
            print(f"[GoPhish] FATAL error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            self.status = "Failed"
            try:
                if monitor.monitoring:
                    monitor.stop()
            except Exception:
                pass
            self.execution_time = time.time() - start_time
            self.metrics        = monitor.get_results()
            return False

    def get_results(self) -> dict:
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
