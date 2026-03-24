"""
Vulnerable Flask Application — 20+ real vulnerability types.

This is a DELIBERATELY VULNERABLE application for testing SecProbe.
NEVER deploy this on a public-facing server.

Vulnerability map:
  /sqli?id=1                → SQL injection (error-based, boolean, time-based)
  /sqli/search?q=test       → SQL injection (LIKE clause)
  /sqli/login               → SQL injection (POST form, auth bypass)
  /xss?name=test            → Reflected XSS (unescaped output)
  /xss/attr?val=test        → XSS in HTML attribute context
  /xss/js?callback=test     → XSS in JavaScript context
  /xss/dom                  → DOM-based XSS (via hash fragment)
  /ssti?name=test           → Server-side template injection (Jinja2)
  /lfi?file=about.txt       → Local file inclusion (path traversal)
  /cmdi?host=127.0.0.1      → OS command injection
  /xxe                      → XML external entity (POST)
  /redirect?url=/           → Open redirect
  /redirect?next=/          → Open redirect (alternate param)
  /ssrf?url=http://x        → Server-side request forgery
  /headers                  → Missing security headers + info leak
  /cookies                  → Insecure cookie flags
  /cors                     → CORS misconfiguration
  /csrf/form                → Form without CSRF protection
  /idor?user_id=1           → Insecure direct object reference
  /info                     → Information disclosure (stack trace, debug info)
  /info/phpinfo             → Simulated phpinfo exposure
  /dir/                     → Directory listing
  /nosql?username=admin     → NoSQL injection (simulated)
  /crlf?lang=en             → CRLF injection in header
  /hpp?page=1               → HTTP parameter pollution
  /upload                   → Unrestricted file upload
"""

import os
import re
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from flask import (
    Flask, request, render_template_string, redirect, make_response,
    jsonify, abort, send_from_directory,
)

app = Flask(__name__)
app.secret_key = "INSECURE_SECRET_KEY_12345"  # Deliberately weak

# ── Database Setup ──────────────────────────────────────────────────

DB_PATH = os.path.join(tempfile.gettempdir(), "secprobe_vulnapp.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        DELETE FROM users;
        DELETE FROM products;
        DELETE FROM comments;
        INSERT INTO users (id, username, password, email, role) VALUES
            (1, 'admin', 'admin123', 'admin@example.com', 'admin'),
            (2, 'john', 'password', 'john@example.com', 'user'),
            (3, 'jane', 'secret', 'jane@example.com', 'user');
        INSERT INTO products (id, name, price, description) VALUES
            (1, 'Widget A', 29.99, 'A standard widget'),
            (2, 'Widget B', 49.99, 'A premium widget'),
            (3, 'Widget C', 9.99, 'A budget widget');
        INSERT INTO comments (id, user_id, content) VALUES
            (1, 1, 'Great product!'),
            (2, 2, 'Needs improvement'),
            (3, 3, 'Love it');
    """)
    conn.commit()
    conn.close()


# ── File Setup ──────────────────────────────────────────────────────

FILES_DIR = os.path.join(tempfile.gettempdir(), "secprobe_vulnapp_files")
os.makedirs(FILES_DIR, exist_ok=True)
Path(os.path.join(FILES_DIR, "about.txt")).write_text("This is the about page.")
Path(os.path.join(FILES_DIR, "readme.txt")).write_text("Read the documentation.")


# ═══════════════════════════════════════════════════════════════════
# INDEX
# ═══════════════════════════════════════════════════════════════════

INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>VulnApp — SecProbe Test Target</title></head>
<body>
<h1>VulnApp — Deliberately Vulnerable</h1>
<!-- TODO: remove debug credentials admin:admin123 -->
<!-- Internal API: http://192.168.1.50:8080/api/v1/ -->
<nav>
  <ul>
    <li><a href="/sqli?id=1">SQL Injection (GET)</a></li>
    <li><a href="/sqli/search?q=widget">SQL Injection (Search)</a></li>
    <li><a href="/sqli/login">SQL Injection (Login)</a></li>
    <li><a href="/xss?name=World">Reflected XSS</a></li>
    <li><a href="/xss/attr?val=test">XSS in Attribute</a></li>
    <li><a href="/xss/js?callback=handleData">XSS in JavaScript</a></li>
    <li><a href="/xss/dom">DOM XSS</a></li>
    <li><a href="/ssti?name=World">SSTI</a></li>
    <li><a href="/lfi?file=about.txt">LFI</a></li>
    <li><a href="/cmdi?host=127.0.0.1">Command Injection</a></li>
    <li><a href="/xxe">XXE (POST)</a></li>
    <li><a href="/redirect?url=/">Open Redirect</a></li>
    <li><a href="/ssrf?url=http://example.com">SSRF</a></li>
    <li><a href="/headers">Security Headers</a></li>
    <li><a href="/cookies">Insecure Cookies</a></li>
    <li><a href="/cors">CORS</a></li>
    <li><a href="/csrf/form">CSRF Form</a></li>
    <li><a href="/idor?user_id=1">IDOR</a></li>
    <li><a href="/info">Info Disclosure</a></li>
    <li><a href="/dir/">Directory Listing</a></li>
    <li><a href="/nosql?username=admin">NoSQL Injection</a></li>
    <li><a href="/crlf?lang=en">CRLF Injection</a></li>
    <li><a href="/hpp?page=1">HTTP Param Pollution</a></li>
    <li><a href="/upload">File Upload</a></li>
    <li><a href="/api/users">API Endpoint</a></li>
  </ul>
</nav>
<form action="/sqli/login" method="POST">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <input type="submit" value="Login">
</form>
</body>
</html>
"""


@app.route("/")
def index():
    resp = make_response(INDEX_HTML)
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    return resp


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTION
# ═══════════════════════════════════════════════════════════════════

@app.route("/sqli")
def sqli_get():
    """Vulnerable to error-based, boolean-based, and UNION-based SQLi."""
    user_id = request.args.get("id", "1")
    conn = get_db()
    try:
        # DELIBERATELY VULNERABLE — string concatenation
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        result = ""
        for row in rows:
            result += f"<p>User: {row['username']} — Email: {row['email']}</p>"
        if not result:
            result = "<p>No user found.</p>"
        return f"""<html><head><title>User Lookup</title></head>
        <body><h1>User Lookup</h1>
        <form><input name="id" value="{user_id}"><input type="submit"></form>
        {result}</body></html>"""
    except Exception as e:
        # DELIBERATELY VULNERABLE — leaks SQL error
        return f"""<html><body><h1>Error</h1>
        <p>SQL Error: {e}</p>
        <p>Query: {query}</p></body></html>""", 500
    finally:
        conn.close()


@app.route("/sqli/search")
def sqli_search():
    """Vulnerable to SQLi in LIKE clause."""
    q = request.args.get("q", "")
    conn = get_db()
    try:
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        items = "".join(f"<li>{r['name']} — ${r['price']}</li>" for r in rows)
        return f"""<html><body><h1>Search Results</h1>
        <form><input name="q" value="{q}"><input type="submit"></form>
        <ul>{items}</ul></body></html>"""
    except Exception as e:
        return f"<html><body><p>Error: {e}</p></body></html>", 500
    finally:
        conn.close()


@app.route("/sqli/login", methods=["GET", "POST"])
def sqli_login():
    """Vulnerable to auth bypass via SQLi."""
    if request.method == "GET":
        return """<html><body><h1>Login</h1>
        <form method="POST" action="/sqli/login">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <input type="submit" value="Login">
        </form></body></html>"""

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    try:
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor = conn.execute(query)
        user = cursor.fetchone()
        if user:
            return f"<html><body><h1>Welcome, {user['username']}!</h1><p>Role: {user['role']}</p></body></html>"
        else:
            return "<html><body><h1>Login Failed</h1><p>Invalid credentials</p></body></html>", 401
    except Exception as e:
        return f"<html><body><p>SQL Error: {e}</p></body></html>", 500
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════
# XSS
# ═══════════════════════════════════════════════════════════════════

@app.route("/xss")
def xss_reflected():
    """Reflected XSS — unescaped output in body."""
    name = request.args.get("name", "World")
    # DELIBERATELY VULNERABLE — no escaping
    return f"""<html><body>
    <h1>Hello {name}!</h1>
    <form><input name="name" value="{name}"><input type="submit"></form>
    </body></html>"""


@app.route("/xss/attr")
def xss_attribute():
    """XSS in HTML attribute context."""
    val = request.args.get("val", "default")
    # DELIBERATELY VULNERABLE — unescaped in attribute
    return f"""<html><body>
    <div id="content" data-value="{val}">Content here</div>
    <input type="text" value="{val}" name="field">
    </body></html>"""


@app.route("/xss/js")
def xss_javascript():
    """XSS in JavaScript context."""
    callback = request.args.get("callback", "handleData")
    # DELIBERATELY VULNERABLE — unescaped in JS
    return f"""<html><body>
    <script>
    var callback = '{callback}';
    function handleData(d) {{ console.log(d); }}
    </script>
    <p>Callback: {callback}</p>
    </body></html>"""


@app.route("/xss/dom")
def xss_dom():
    """DOM-based XSS via hash/search."""
    return """<html><body>
    <h1>DOM XSS Test</h1>
    <div id="output"></div>
    <script>
    var data = document.location.hash.substring(1);
    document.getElementById('output').innerHTML = data;
    var q = new URLSearchParams(location.search).get('q');
    if (q) { document.write('Search: ' + q); }
    </script>
    </body></html>"""


# ═══════════════════════════════════════════════════════════════════
# SSTI
# ═══════════════════════════════════════════════════════════════════

@app.route("/ssti")
def ssti():
    """Jinja2 Server-Side Template Injection."""
    name = request.args.get("name", "World")
    # DELIBERATELY VULNERABLE — user input in template
    template = f"<html><body><h1>Hello {name}!</h1></body></html>"
    return render_template_string(template)


# ═══════════════════════════════════════════════════════════════════
# LFI
# ═══════════════════════════════════════════════════════════════════

@app.route("/lfi")
def lfi():
    """Local File Inclusion via path traversal."""
    filename = request.args.get("file", "about.txt")
    # DELIBERATELY VULNERABLE — no path sanitization
    filepath = os.path.join(FILES_DIR, filename)
    try:
        content = open(filepath).read()
        return f"<html><body><h1>File Viewer</h1><pre>{content}</pre></body></html>"
    except FileNotFoundError:
        return f"<html><body><p>File not found: {filename}</p></body></html>", 404
    except Exception as e:
        return f"<html><body><p>Error: {e}</p></body></html>", 500


# ═══════════════════════════════════════════════════════════════════
# COMMAND INJECTION
# ═══════════════════════════════════════════════════════════════════

@app.route("/cmdi")
def cmdi():
    """OS Command Injection via ping."""
    host = request.args.get("host", "127.0.0.1")
    # DELIBERATELY VULNERABLE — shell injection
    try:
        output = subprocess.check_output(
            f"echo Pinging {host}",  # Using echo for safety in tests
            shell=True, stderr=subprocess.STDOUT, timeout=5,
        ).decode()
        return f"""<html><body><h1>Ping Tool</h1>
        <form><input name="host" value="{host}"><input type="submit"></form>
        <pre>{output}</pre></body></html>"""
    except subprocess.TimeoutExpired:
        return "<html><body><p>Timeout</p></body></html>", 504
    except Exception as e:
        return f"<html><body><p>Error: {e}</p></body></html>", 500


# ═══════════════════════════════════════════════════════════════════
# XXE
# ═══════════════════════════════════════════════════════════════════

@app.route("/xxe", methods=["GET", "POST"])
def xxe():
    """XML External Entity Injection."""
    if request.method == "GET":
        return """<html><body><h1>XML Parser</h1>
        <form method="POST" action="/xxe" enctype="text/xml">
        <textarea name="xml" rows="10" cols="60">&lt;root&gt;&lt;name&gt;test&lt;/name&gt;&lt;/root&gt;</textarea>
        <br><input type="submit" value="Parse XML">
        </form></body></html>"""

    # Accept raw XML body or form data
    xml_data = request.data.decode("utf-8") if request.data else request.form.get("xml", "")
    if not xml_data:
        return "<html><body><p>No XML data</p></body></html>", 400

    try:
        import xml.etree.ElementTree as ET
        # DELIBERATELY VULNERABLE — allows entity expansion
        # In a real vulnerable app, this would use a parser that resolves entities
        root = ET.fromstring(xml_data)
        text = ET.tostring(root, encoding="unicode")
        return f"<html><body><h1>Parsed XML</h1><pre>{text}</pre></body></html>"
    except ET.ParseError as e:
        return f"<html><body><p>XML Parse Error: {e}</p></body></html>", 400


# ═══════════════════════════════════════════════════════════════════
# OPEN REDIRECT
# ═══════════════════════════════════════════════════════════════════

@app.route("/redirect")
def open_redirect():
    """Open redirect — no validation."""
    url = request.args.get("url") or request.args.get("next") or "/"
    # DELIBERATELY VULNERABLE — unvalidated redirect
    return redirect(url)


# ═══════════════════════════════════════════════════════════════════
# SSRF
# ═══════════════════════════════════════════════════════════════════

@app.route("/ssrf")
def ssrf():
    """Server-Side Request Forgery."""
    target_url = request.args.get("url", "")
    if not target_url:
        return """<html><body><h1>URL Fetcher</h1>
        <form><input name="url" placeholder="http://..." size="40"><input type="submit"></form>
        </body></html>"""

    # DELIBERATELY VULNERABLE — fetches any URL
    try:
        import urllib.request
        resp = urllib.request.urlopen(target_url, timeout=3)
        content = resp.read(4096).decode("utf-8", errors="replace")
        return f"<html><body><h1>Fetched Content</h1><pre>{content[:2000]}</pre></body></html>"
    except Exception as e:
        return f"<html><body><p>Fetch Error: {e}</p></body></html>", 500


# ═══════════════════════════════════════════════════════════════════
# SECURITY HEADERS / INFO DISCLOSURE
# ═══════════════════════════════════════════════════════════════════

@app.route("/headers")
def bad_headers():
    """Missing security headers + info leak headers."""
    resp = make_response("<html><body><h1>Headers Test</h1></body></html>")
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    resp.headers["X-Debug-Token"] = "abc123"
    resp.headers["X-AspNet-Version"] = "4.0.30319"
    # Deliberately NO security headers (no HSTS, no CSP, no X-Frame-Options, etc.)
    return resp


@app.route("/cookies")
def bad_cookies():
    """Insecure cookie flags."""
    resp = make_response("<html><body><h1>Cookie Test</h1></body></html>")
    resp.set_cookie("session_id", "abc123def456", httponly=False, secure=False, samesite=None)
    resp.set_cookie("admin_token", "supersecret", httponly=False, secure=False)
    resp.set_cookie("preferences", "dark_mode=true")
    return resp


@app.route("/cors")
def cors_misconfigured():
    """CORS misconfiguration — reflects Origin."""
    origin = request.headers.get("Origin", "*")
    resp = make_response("<html><body><h1>CORS Test</h1></body></html>")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
    return resp


# ═══════════════════════════════════════════════════════════════════
# CSRF
# ═══════════════════════════════════════════════════════════════════

@app.route("/csrf/form", methods=["GET", "POST"])
def csrf_form():
    """Form without CSRF token protection."""
    if request.method == "POST":
        email = request.form.get("email", "")
        return f"<html><body><p>Email changed to: {email}</p></body></html>"

    # DELIBERATELY VULNERABLE — no CSRF token
    return """<html><body><h1>Change Email</h1>
    <form method="POST" action="/csrf/form">
    <input name="email" placeholder="new@email.com">
    <input type="submit" value="Change Email">
    </form></body></html>"""


# ═══════════════════════════════════════════════════════════════════
# IDOR
# ═══════════════════════════════════════════════════════════════════

@app.route("/idor")
def idor():
    """Insecure Direct Object Reference — no auth check."""
    user_id = request.args.get("user_id", "1")
    conn = get_db()
    try:
        # DELIBERATELY VULNERABLE — no authorization check
        cursor = conn.execute(f"SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return f"""<html><body><h1>User Profile</h1>
            <p>Username: {user['username']}</p>
            <p>Email: {user['email']}</p>
            <p>Role: {user['role']}</p>
            </body></html>"""
        return "<html><body><p>User not found</p></body></html>", 404
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════
# INFO DISCLOSURE
# ═══════════════════════════════════════════════════════════════════

@app.route("/info")
def info_disclosure():
    """Simulated error page with stack trace and sensitive info."""
    return """<html><body>
    <h1>Application Error</h1>
    <p>Traceback (most recent call last):
      File "/var/www/app/main.py", line 42, in handle_request
        result = db.query(user_input)
      File "/var/www/app/models.py", line 15, in query
        cursor.execute(sql)
    sqlite3.OperationalError: near "DROP": syntax error</p>
    <hr>
    <p>Debug Info:</p>
    <p>Database: sqlite:///var/www/app/data.db</p>
    <p>password="SuperSecretDB123"</p>
    <p>AKIAIOSFODNN7EXAMPLEKEY</p>
    <p>Internal server: 10.0.1.50:3306</p>
    <p>-----BEGIN RSA PRIVATE KEY-----</p>
    <p>sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDE</p>
    </body></html>""", 500


@app.route("/info/phpinfo")
def phpinfo():
    """Simulated PHP info page."""
    return """<html><body>
    <h1>PHP Version 7.4.3</h1>
    <table><tr><td>System</td><td>Linux srv01 5.4.0-42-generic</td></tr>
    <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
    <tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>
    <tr><td>MYSQL_PASSWORD</td><td>root_pass_123</td></tr>
    </table>
    </body></html>"""


# ═══════════════════════════════════════════════════════════════════
# DIRECTORY LISTING
# ═══════════════════════════════════════════════════════════════════

@app.route("/dir/")
def directory_listing():
    """Simulated directory listing."""
    return """<html><head><title>Index of /uploads</title></head><body>
    <h1>Index of /uploads</h1>
    <table>
    <tr><td><a href="../">Parent Directory</a></td></tr>
    <tr><td><a href="backup.sql">backup.sql</a></td><td>2024-01-15 10:30</td><td>45MB</td></tr>
    <tr><td><a href="config.php.bak">config.php.bak</a></td><td>2024-01-14 09:15</td><td>2KB</td></tr>
    <tr><td><a href="users.csv">users.csv</a></td><td>2024-01-13 16:00</td><td>120KB</td></tr>
    </table></body></html>"""


# ═══════════════════════════════════════════════════════════════════
# NOSQL INJECTION (simulated)
# ═══════════════════════════════════════════════════════════════════

@app.route("/nosql")
def nosql():
    """Simulated NoSQL injection — responds differently to operator injection."""
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # Simulate MongoDB-like behavior: if operator chars present, return all
    if "$" in username or "{" in username or "$" in password:
        return """<html><body><h1>Users</h1>
        <p>admin — admin@example.com</p>
        <p>john — john@example.com</p>
        <p>jane — jane@example.com</p>
        </body></html>"""

    # Normal lookup
    conn = get_db()
    try:
        cursor = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        user = cursor.fetchone()
        if user:
            return f"<html><body><p>Found: {user['username']}</p></body></html>"
        return "<html><body><p>User not found</p></body></html>", 404
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════
# CRLF INJECTION
# ═══════════════════════════════════════════════════════════════════

@app.route("/crlf")
def crlf():
    """CRLF injection in response header."""
    lang = request.args.get("lang", "en")
    resp = make_response(f"<html><body><h1>Language: {lang}</h1></body></html>")
    # DELIBERATELY VULNERABLE — unvalidated header value
    resp.headers["X-Language"] = lang
    return resp


# ═══════════════════════════════════════════════════════════════════
# HPP
# ═══════════════════════════════════════════════════════════════════

@app.route("/hpp")
def hpp():
    """HTTP Parameter Pollution."""
    page = request.args.get("page", "1")
    sort = request.args.get("sort", "name")
    # Returns all values of duplicated params
    all_pages = request.args.getlist("page")
    all_sorts = request.args.getlist("sort")
    return f"""<html><body><h1>Listing</h1>
    <p>Page: {page} (all: {all_pages})</p>
    <p>Sort: {sort} (all: {all_sorts})</p>
    </body></html>"""


# ═══════════════════════════════════════════════════════════════════
# FILE UPLOAD
# ═══════════════════════════════════════════════════════════════════

@app.route("/upload", methods=["GET", "POST"])
def upload():
    """Unrestricted file upload."""
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # DELIBERATELY VULNERABLE — no extension check, no size limit
            filename = f.filename
            return f"<html><body><p>Uploaded: {filename}</p></body></html>"
        return "<html><body><p>No file</p></body></html>", 400

    return """<html><body><h1>File Upload</h1>
    <form method="POST" enctype="multipart/form-data" action="/upload">
    <input type="file" name="file">
    <input type="submit" value="Upload">
    </form></body></html>"""


# ═══════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/users")
def api_users():
    """API endpoint returning JSON — no auth required."""
    conn = get_db()
    try:
        cursor = conn.execute("SELECT id, username, email, role FROM users")
        users = [dict(row) for row in cursor.fetchall()]
        return jsonify({"users": users, "total": len(users)})
    finally:
        conn.close()


@app.route("/api/user/<int:uid>")
def api_user(uid):
    """API endpoint with IDOR."""
    conn = get_db()
    try:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
        user = cursor.fetchone()
        if user:
            # DELIBERATELY VULNERABLE — exposes password
            return jsonify(dict(user))
        return jsonify({"error": "not found"}), 404
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLER (leaks info)
# ═══════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return f"""<html><body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found.</p>
    <p>Server: Apache/2.4.41 (Ubuntu)</p>
    </body></html>""", 404


@app.errorhandler(500)
def server_error(e):
    import traceback
    return f"""<html><body>
    <h1>500 Internal Server Error</h1>
    <pre>{traceback.format_exc()}</pre>
    </body></html>""", 500


# ═══════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════

def create_app():
    """Factory for test usage."""
    init_db()
    return app


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5555, debug=False)
