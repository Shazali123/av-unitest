# AV-Unitest — Modular Antivirus Benchmark Platform
# Copyright (c) 2026 Shazali. Licensed under GPL-3.0.
"""
AV-Unitest Flask Backend — Unified API Server
Replaces upload_results.php, get_results.php, and api.py
Serves the dashboard and handles benchmark result uploads.
"""

import os
import json
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder='.', static_url_path='')

# CORS — restrict to own domain in production
ALLOWED_ORIGINS = os.environ.get(
    'CORS_ORIGINS', 'https://av-unitest.onrender.com'
).split(',')
CORS(app, origins=ALLOWED_ORIGINS)

# API key for upload protection (OWASP A01)
API_KEY = os.environ.get('AV_UNITEST_API_KEY', 'av-unitest-default-key-change-me')

# Latest tool version (for auto-update checker)
LATEST_VERSION = os.environ.get('LATEST_VERSION', '1.0.0')
DOWNLOAD_URL = os.environ.get(
    'DOWNLOAD_URL',
    'https://github.com/Shazali123/av-unitest/releases/latest'
)

# Logging (OWASP A09)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database setup — SQLite locally, PostgreSQL on Render
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get('DATABASE_URL', '')

if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    # PostgreSQL (Render production)
    import psycopg2
    DB_TYPE = 'postgres'

    def get_db():
        conn = psycopg2.connect(DATABASE_URL)
        return conn

    def init_db():
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS benchmark_results (
                id SERIAL PRIMARY KEY,
                run_id TEXT UNIQUE,
                av_name TEXT NOT NULL,
                os_info TEXT DEFAULT '',
                timestamp TEXT NOT NULL,
                total_score REAL DEFAULT 0,
                detection_score REAL DEFAULT 0,
                performance_score REAL DEFAULT 0,
                results_json TEXT DEFAULT '{}',
                breakdown_json TEXT DEFAULT '{}',
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT DEFAULT ''
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("PostgreSQL database initialized")

else:
    # SQLite (local development)
    import sqlite3
    DB_TYPE = 'sqlite'
    DB_PATH = os.path.join(os.path.dirname(__file__), 'benchmark.db')

    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db():
        conn = get_db()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS benchmark_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT UNIQUE,
                av_name TEXT NOT NULL,
                os_info TEXT DEFAULT '',
                timestamp TEXT NOT NULL,
                total_score REAL DEFAULT 0,
                detection_score REAL DEFAULT 0,
                performance_score REAL DEFAULT 0,
                results_json TEXT DEFAULT '{}',
                breakdown_json TEXT DEFAULT '{}',
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT DEFAULT ''
            )
        ''')
        conn.commit()
        conn.close()
        logger.info(f"SQLite database initialized at {DB_PATH}")


# ---------------------------------------------------------------------------
# Rate limiting (OWASP — prevent abuse)
# ---------------------------------------------------------------------------

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100 per hour"],
        storage_uri="memory://"
    )
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False
    logger.warning("flask-limiter not installed — rate limiting disabled")


# ---------------------------------------------------------------------------
# Security middleware
# ---------------------------------------------------------------------------

@app.before_request
def security_checks():
    """OWASP A01 + input validation."""
    # API key check for uploads
    if request.path == '/api/upload' and request.method == 'POST':
        key = request.headers.get('X-API-Key', '')
        if key != API_KEY:
            logger.warning(f"Unauthorized upload attempt from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized'}), 403

        # Payload size check (1MB max)
        if request.content_length and request.content_length > 1_000_000:
            return jsonify({'error': 'Payload too large'}), 413


@app.after_request
def add_security_headers(response):
    """OWASP A07 — Content Security Policy + security headers."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if request.path == '/' or request.path.endswith('.html'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.datatables.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
    return response


# ---------------------------------------------------------------------------
# Helper: execute parameterized query (OWASP A03 — injection prevention)
# ---------------------------------------------------------------------------

def query_db(sql, params=(), fetchone=False, commit=False):
    """Execute a parameterized SQL query. Returns rows as dicts."""
    conn = get_db()
    if DB_TYPE == 'postgres':
        # PostgreSQL uses %s placeholders
        sql = sql.replace('?', '%s')
        cur = conn.cursor()
        cur.execute(sql, params)
        if commit:
            conn.commit()
            conn.close()
            return None
        if fetchone:
            row = cur.fetchone()
            if row:
                cols = [desc[0] for desc in cur.description]
                conn.close()
                return dict(zip(cols, row))
            conn.close()
            return None
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        conn.close()
        return [dict(zip(cols, row)) for row in rows]
    else:
        # SQLite
        cur = conn.execute(sql, params)
        if commit:
            conn.commit()
            conn.close()
            return None
        if fetchone:
            row = cur.fetchone()
            conn.close()
            return dict(row) if row else None
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the dashboard."""
    return send_from_directory('.', 'index.html')


@app.route('/api/version', methods=['GET'])
def get_version():
    """Auto-update checker endpoint."""
    return jsonify({
        'version': LATEST_VERSION,
        'download_url': DOWNLOAD_URL,
    })


@app.route('/api/upload', methods=['POST'])
def upload_results():
    """Receive benchmark results from AV-Unitest.exe."""
    try:
        data = request.get_json(force=True)

        # Input validation (OWASP)
        required = ['run_id', 'av_name', 'timestamp']
        for field in required:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        # Sanitize string fields
        run_id = str(data['run_id'])[:100]
        av_name = str(data['av_name'])[:100]
        os_info = str(data.get('os_info', ''))[:200]
        timestamp = str(data['timestamp'])[:50]

        # Score validation
        total = min(max(float(data.get('total_score', 0)), 0), 10)
        detection = min(max(float(data.get('detection_score', 0)), 0), 6)
        performance = min(max(float(data.get('performance_score', 0)), 0), 4)

        results_json = json.dumps(data.get('module_results', []))
        breakdown_json = json.dumps(data.get('breakdown', {}))

        query_db(
            '''INSERT INTO benchmark_results
               (run_id, av_name, os_info, timestamp, total_score,
                detection_score, performance_score, results_json,
                breakdown_json, client_ip)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (run_id, av_name, os_info, timestamp, total, detection,
             performance, results_json, breakdown_json,
             request.remote_addr or ''),
            commit=True
        )

        logger.info(f"Upload: {av_name} | score={total} | from={request.remote_addr}")
        return jsonify({'status': 'ok', 'run_id': run_id}), 201

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/results', methods=['GET'])
def get_results():
    """List benchmark results with optional filters."""
    av_filter = request.args.get('av', '')
    limit = min(int(request.args.get('limit', 100)), 500)
    sort = request.args.get('sort', 'timestamp')

    # Whitelist sort columns (OWASP A03)
    allowed_sorts = ['timestamp', 'total_score', 'av_name', 'detection_score']
    if sort not in allowed_sorts:
        sort = 'timestamp'

    if av_filter:
        rows = query_db(
            f'SELECT * FROM benchmark_results WHERE av_name = ? ORDER BY {sort} DESC LIMIT ?',
            (av_filter, limit)
        )
    else:
        rows = query_db(
            f'SELECT * FROM benchmark_results ORDER BY {sort} DESC LIMIT ?',
            (limit,)
        )

    # Parse JSON fields
    for row in rows:
        try:
            row['module_results'] = json.loads(row.get('results_json', '[]'))
        except (json.JSONDecodeError, TypeError):
            row['module_results'] = []
        try:
            row['breakdown'] = json.loads(row.get('breakdown_json', '{}'))
        except (json.JSONDecodeError, TypeError):
            row['breakdown'] = {}

    return jsonify(rows)


@app.route('/api/results/<run_id>', methods=['GET'])
def get_result_detail(run_id):
    """Get a single benchmark result by run_id."""
    row = query_db(
        'SELECT * FROM benchmark_results WHERE run_id = ?',
        (run_id,), fetchone=True
    )
    if not row:
        return jsonify({'error': 'Not found'}), 404

    try:
        row['module_results'] = json.loads(row.get('results_json', '[]'))
    except (json.JSONDecodeError, TypeError):
        row['module_results'] = []
    try:
        row['breakdown'] = json.loads(row.get('breakdown_json', '{}'))
    except (json.JSONDecodeError, TypeError):
        row['breakdown'] = {}

    return jsonify(row)


@app.route('/api/summary', methods=['GET'])
def get_summary():
    """Per-AV aggregated statistics."""
    rows = query_db('''
        SELECT av_name,
               COUNT(*) as run_count,
               ROUND(AVG(total_score), 2) as avg_total,
               ROUND(AVG(detection_score), 2) as avg_detection,
               ROUND(AVG(performance_score), 2) as avg_performance,
               ROUND(MAX(total_score), 2) as best_total,
               ROUND(MIN(total_score), 2) as worst_total
        FROM benchmark_results
        GROUP BY av_name
        ORDER BY avg_total DESC
    ''')
    return jsonify(rows)


@app.route('/api/avs', methods=['GET'])
def get_avs():
    """List unique AV names."""
    rows = query_db('SELECT DISTINCT av_name FROM benchmark_results ORDER BY av_name')
    return jsonify([r['av_name'] for r in rows])


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

# Initialize database on import
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
