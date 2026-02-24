"""
GoPhish Diagnostic Script
Run this on the TEST VM to see exactly what's failing.
Usage: python gophish_diag.py
"""

import json, ssl, urllib.request, urllib.error, os, sys

CONFIG_PATH = os.path.join(os.path.dirname(__file__),
                           'modules', 'module_2_gophish', 'gophish_config.json')

def load_cfg():
    with open(CONFIG_PATH) as f:
        return json.load(f)

def req(host, api_key, path, method='GET', data=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"{host}/api{path}?api_key={api_key}"
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, method=method)
    r.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        print(f"  HTTP {e.code}: {body_err}")
        return e.code, {}
    except Exception as e:
        print(f"  EXCEPTION: {type(e).__name__}: {e}")
        return 0, {}

cfg = load_cfg()
HOST = cfg['host']
KEY  = cfg['api_key']

print("=" * 60)
print(f"GoPhish Diagnostic")
print(f"Host  : {HOST}")
print(f"APIKey: {KEY[:8]}...{KEY[-4:]}")
print("=" * 60)

# 1. Basic connectivity
print("\n[1] Basic connection test (/api/campaigns/)...")
code, data = req(HOST, KEY, '/campaigns/')
print(f"    Status: {code}  |  Response type: {type(data).__name__}")
if code == 200:
    print(f"    OK - {len(data)} campaigns found")
else:
    print("    FAIL - cannot connect")
    sys.exit(1)

# 2. SMTP profiles
print("\n[2] SMTP Profiles (/api/smtp/)...")
code, data = req(HOST, KEY, '/smtp/')
print(f"    Status: {code}")
if isinstance(data, list):
    if data:
        for s in data:
            print(f"    - '{s.get('name')}' (id={s.get('id')})")
    else:
        print("    WARNING: No SMTP profiles found! Create one in GoPhish UI.")
elif isinstance(data, dict):
    print(f"    Raw response: {json.dumps(data)[:200]}")

# 3. Email templates
print("\n[3] Email Templates (/api/templates/)...")
code, data = req(HOST, KEY, '/templates/')
print(f"    Status: {code}")
if isinstance(data, list):
    if data:
        for t in data:
            print(f"    - '{t.get('name')}' (id={t.get('id')})")
    else:
        print("    WARNING: No email templates found!")
elif isinstance(data, dict):
    print(f"    Raw response: {json.dumps(data)[:200]}")

# 4. Landing pages
print("\n[4] Landing Pages (/api/pages/)...")
code, data = req(HOST, KEY, '/pages/')
print(f"    Status: {code}")
if isinstance(data, list):
    if data:
        for p in data:
            print(f"    - '{p.get('name')}' (id={p.get('id')})")
    else:
        print("    WARNING: No landing pages found!")
elif isinstance(data, dict):
    print(f"    Raw response: {json.dumps(data)[:200]}")

# 5. Config name matching
print("\n[5] Config name matching...")
cfg_smtp = cfg.get('smtp_profile','')
cfg_tpl  = cfg.get('email_template','')
cfg_page = cfg.get('landing_page','')
print(f"    Expected SMTP    : '{cfg_smtp}'")
print(f"    Expected Template: '{cfg_tpl}'")
print(f"    Expected Page    : '{cfg_page}'")

code, smtp_list = req(HOST, KEY, '/smtp/')
code, tpl_list  = req(HOST, KEY, '/templates/')
code, page_list = req(HOST, KEY, '/pages/')

def find(items, name):
    if not isinstance(items, list): return None
    for i in items:
        if isinstance(i, dict) and i.get('name','').lower() == name.lower():
            return i
    return None

smtp_match = find(smtp_list, cfg_smtp)
tpl_match  = find(tpl_list, cfg_tpl)
page_match = find(page_list, cfg_page)

print(f"    SMTP match      : {'OK - found' if smtp_match else 'MISSING'}")
print(f"    Template match  : {'OK - found' if tpl_match else 'MISSING'}")
print(f"    Page match      : {'OK - found' if page_match else 'MISSING'}")

print("\n" + "=" * 60)
all_ok = smtp_match and tpl_match and page_match
if all_ok:
    print("ALL OK - GoPhish should work. Check for other errors.")
else:
    print("FIX NEEDED - See MISSING items above.")
    print("Create them in the GoPhish web UI at:")
    print(f"  {HOST}")
print("=" * 60)
