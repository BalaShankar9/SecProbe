"""
File Upload Scanner — CWE-434: Unrestricted upload of dangerous file types.

Detection strategy:
  1. Discover upload forms (file inputs, multipart endpoints)
  2. Test extension bypass: .php, .phtml, .php5, .pht, .asp, .aspx, .jsp
  3. Double extension: shell.php.jpg, shell.jpg.php
  4. Null byte: shell.php%00.jpg
  5. MIME type manipulation: Content-Type mismatch
  6. Magic bytes: GIF89a header + PHP code
  7. SVG with embedded script
  8. .htaccess upload → execute arbitrary extensions
  9. Polyglot files (GIFAR, etc.)
"""

import re
import time
import uuid
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Dangerous extensions by platform
DANGEROUS_EXTENSIONS = {
    "php": [".php", ".phtml", ".php5", ".php7", ".pht", ".phar", ".phps",
            ".php3", ".php4", ".pHP", ".PhP"],
    "asp": [".asp", ".aspx", ".asa", ".asax", ".ashx", ".asmx", ".cer"],
    "jsp": [".jsp", ".jspx", ".jsw", ".jsv", ".jtml"],
    "python": [".py", ".pyc"],
    "perl": [".pl", ".cgi"],
    "shell": [".sh", ".bash"],
    "config": [".htaccess", ".config", "web.config", ".env"],
    "ssi": [".shtml", ".stm", ".shtm"],
}

# Test payloads by type
UPLOAD_PAYLOADS = {
    "php_webshell": {
        "content": b'<?php echo "SECPROBE_UPLOAD_CHECK_" . md5("secprobe"); ?>',
        "content_type": "application/x-php",
        "marker": "SECPROBE_UPLOAD_CHECK_",
    },
    "php_gif_polyglot": {
        "content": b'GIF89a<?php echo "SECPROBE_UPLOAD_CHECK_" . md5("secprobe"); ?>',
        "content_type": "image/gif",
        "marker": "SECPROBE_UPLOAD_CHECK_",
    },
    "asp_webshell": {
        "content": b'<% Response.Write("SECPROBE_UPLOAD_CHECK_" & "asp") %>',
        "content_type": "application/octet-stream",
        "marker": "SECPROBE_UPLOAD_CHECK_",
    },
    "jsp_webshell": {
        "content": b'<%= "SECPROBE_UPLOAD_CHECK_" + "jsp" %>',
        "content_type": "application/octet-stream",
        "marker": "SECPROBE_UPLOAD_CHECK_",
    },
    "svg_xss": {
        "content": b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("SECPROBE_XSS")</script></svg>',
        "content_type": "image/svg+xml",
        "marker": "SECPROBE_XSS",
    },
    "html_injection": {
        "content": b'<html><body><script>document.write("SECPROBE_UPLOAD_CHECK_")</script></body></html>',
        "content_type": "text/html",
        "marker": "SECPROBE_UPLOAD_CHECK_",
    },
    "htaccess": {
        "content": b'AddType application/x-httpd-php .txt\nAddHandler php-script .txt',
        "content_type": "text/plain",
        "marker": None,
    },
}


class UploadScanner(SmartScanner):
    name = "Upload Scanner"
    description = "Test for unrestricted file upload vulnerabilities (CWE-434)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing file upload on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except Exception as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        # ── Phase 1: Discover upload endpoints ───────────────────────
        upload_forms = self._discover_upload_forms(url, baseline.text)
        if self.context:
            for form in self.context.get_injectable_forms():
                if any("file" in f.lower() for f in form.get("fields", {})):
                    upload_forms.append(form)

        vulns_found = 0

        if not upload_forms:
            # Probe common upload paths
            common_paths = [
                "/upload", "/api/upload", "/api/v1/upload",
                "/file/upload", "/media/upload", "/images/upload",
                "/admin/upload", "/wp-admin/async-upload.php",
                "/api/files", "/upload.php", "/upload.asp",
            ]
            for path in common_paths:
                test_url = urljoin(url, path)
                try:
                    resp = self.http_client.options(test_url, timeout=5)
                    if resp.status_code < 405:
                        upload_forms.append({
                            "action": test_url,
                            "method": "POST",
                            "fields": {"file": ""},
                            "is_probe": True,
                        })
                except Exception:
                    pass

        if not upload_forms:
            print_status("No upload endpoints discovered.", "info")
            self.add_finding(
                title="No file upload endpoints detected",
                severity=Severity.INFO,
                description="Could not find file upload forms or endpoints.",
                category="File Upload",
            )
            return

        print_status(f"Found {len(upload_forms)} potential upload endpoint(s)", "info")

        # ── Phase 2: Extension bypass testing ────────────────────────
        print_status("Phase 2: Testing extension bypasses", "progress")
        for form in upload_forms:
            action = form.get("action", url)
            field_name = self._get_file_field(form)

            for platform, exts in DANGEROUS_EXTENSIONS.items():
                for ext in exts[:3]:  # Top 3 per platform
                    if self.config.rate_limit:
                        time.sleep(self.config.rate_limit)

                    filename = f"secprobe_test_{uuid.uuid4().hex[:6]}{ext}"
                    payload_key = f"{platform}_webshell"
                    payload_info = UPLOAD_PAYLOADS.get(payload_key, UPLOAD_PAYLOADS["php_webshell"])

                    result = self._try_upload(action, field_name, filename,
                                              payload_info["content"],
                                              payload_info["content_type"])
                    if result and result.get("uploaded"):
                        vulns_found += 1
                        executed = result.get("executed", False)
                        sev = Severity.CRITICAL if executed else Severity.HIGH
                        self.add_finding(
                            title=f"File Upload - {ext} accepted{' + EXECUTED' if executed else ''}",
                            severity=sev,
                            description=(
                                f"Server accepted upload of {ext} file.\n"
                                f"{'Code executed on server!' if executed else 'File stored but execution not confirmed.'}\n"
                                f"Platform: {platform}"
                            ),
                            recommendation="Validate file extensions server-side with allow-list. Store outside webroot.",
                            evidence=f"URL: {action}\nFilename: {filename}\nField: {field_name}",
                            category="File Upload", url=action, cwe="CWE-434",
                        )
                        print_finding(sev, f"Upload: {ext} {'EXECUTED' if executed else 'accepted'}")

        # ── Phase 3: Double extension bypass ─────────────────────────
        print_status("Phase 3: Double extension bypass", "progress")
        for form in upload_forms:
            action = form.get("action", url)
            field_name = self._get_file_field(form)

            double_exts = [
                "shell.php.jpg", "shell.php.png", "shell.php.gif",
                "shell.jpg.php", "shell.asp.jpg", "shell.jsp.png",
                "shell.php%00.jpg", "shell.php\x00.jpg",
                "shell.pHp.JpG",
            ]
            for filename in double_exts:
                result = self._try_upload(action, field_name, filename,
                                          UPLOAD_PAYLOADS["php_webshell"]["content"],
                                          "image/jpeg")
                if result and result.get("uploaded"):
                    vulns_found += 1
                    self.add_finding(
                        title=f"File Upload - Double extension bypass ({filename})",
                        severity=Severity.HIGH,
                        description=f"Server accepted double-extension file: {filename}",
                        recommendation="Parse and validate the LAST extension only.",
                        evidence=f"URL: {action}\nFilename: {filename}",
                        category="File Upload", url=action, cwe="CWE-434",
                    )
                    break

        # ── Phase 4: MIME type mismatch ──────────────────────────────
        print_status("Phase 4: MIME type manipulation", "progress")
        for form in upload_forms:
            action = form.get("action", url)
            field_name = self._get_file_field(form)

            # Upload PHP with image Content-Type
            result = self._try_upload(action, field_name, "test.php",
                                      UPLOAD_PAYLOADS["php_webshell"]["content"],
                                      "image/jpeg")
            if result and result.get("uploaded"):
                vulns_found += 1
                self.add_finding(
                    title="File Upload - MIME type bypass (PHP as image/jpeg)",
                    severity=Severity.HIGH,
                    description="Server accepts .php file with image/jpeg Content-Type.",
                    recommendation="Validate both extension AND content, not just Content-Type.",
                    evidence=f"URL: {action}",
                    category="File Upload", url=action, cwe="CWE-434",
                )

        # ── Phase 5: Magic bytes polyglot ────────────────────────────
        for form in upload_forms:
            action = form.get("action", url)
            field_name = self._get_file_field(form)

            result = self._try_upload(action, field_name, "polyglot.php.gif",
                                      UPLOAD_PAYLOADS["php_gif_polyglot"]["content"],
                                      "image/gif")
            if result and result.get("uploaded"):
                vulns_found += 1
                self.add_finding(
                    title="File Upload - GIF/PHP polyglot accepted",
                    severity=Severity.HIGH,
                    description="Server accepted a GIF89a + PHP polyglot file.",
                    recommendation="Validate file content beyond magic bytes. Use image reprocessing.",
                    evidence=f"URL: {action}",
                    category="File Upload", url=action, cwe="CWE-434",
                )

        # ── Phase 6: SVG XSS upload ──────────────────────────────────
        for form in upload_forms:
            action = form.get("action", url)
            field_name = self._get_file_field(form)

            result = self._try_upload(action, field_name, "test.svg",
                                      UPLOAD_PAYLOADS["svg_xss"]["content"],
                                      "image/svg+xml")
            if result and result.get("uploaded"):
                vulns_found += 1
                self.add_finding(
                    title="File Upload - SVG with embedded XSS",
                    severity=Severity.MEDIUM,
                    description="Server accepts SVG files with embedded JavaScript.",
                    recommendation="Sanitize SVG uploads. Strip script tags from SVG content.",
                    evidence=f"URL: {action}",
                    category="File Upload", url=action, cwe="CWE-79",
                )

        if vulns_found == 0:
            print_status("No file upload vulnerabilities detected.", "success")
            self.add_finding(
                title="No file upload vulnerabilities detected",
                severity=Severity.INFO,
                description="Automated tests did not detect upload vulnerabilities.",
                category="File Upload",
            )

    def _discover_upload_forms(self, url, html):
        """Find forms with file input fields."""
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            if 'type="file"' in form_html.lower() or "type='file'" in form_html.lower():
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                action = action_match.group(1) if action_match else url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                fields = {}
                for inp in re.finditer(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE):
                    inp_html = inp.group(0)
                    name = inp.group(1)
                    if 'type="file"' in inp_html.lower() or "type='file'" in inp_html.lower():
                        fields[name] = "__FILE__"
                    else:
                        val_match = re.search(r'value=["\']([^"\']*)["\']', inp_html)
                        fields[name] = val_match.group(1) if val_match else "test"
                forms.append({"action": action, "method": "POST", "fields": fields})
        return forms

    def _get_file_field(self, form):
        """Get the file input field name from a form."""
        for name, val in form.get("fields", {}).items():
            if val == "__FILE__" or "file" in name.lower():
                return name
        return "file"

    def _try_upload(self, url, field_name, filename, content, content_type):
        """Attempt to upload a file and check if it was accepted."""
        try:
            files = {field_name: (filename, content, content_type)}
            resp = self.http_client.post(url, files=files, timeout=10)

            uploaded = False
            executed = False

            # Check if upload was accepted (not rejected)
            if resp.status_code in (200, 201, 202, 301, 302):
                # Look for rejection indicators
                rejection_words = ["not allowed", "invalid", "rejected", "forbidden",
                                   "error", "unsupported", "blocked"]
                resp_lower = resp.text.lower()
                if not any(w in resp_lower for w in rejection_words):
                    uploaded = True

                # Check if code was executed
                for payload in UPLOAD_PAYLOADS.values():
                    marker = payload.get("marker")
                    if marker and marker in resp.text:
                        executed = True
                        break

                # Try to find the uploaded file URL
                if uploaded:
                    url_patterns = [
                        re.compile(r'"(?:url|path|file|link)":\s*"([^"]+)"', re.IGNORECASE),
                        re.compile(r'src=["\']([^"\']*' + re.escape(filename.split('.')[0]) + r'[^"\']*)["\']'),
                    ]
                    for pattern in url_patterns:
                        m = pattern.search(resp.text)
                        if m:
                            file_url = m.group(1)
                            if not file_url.startswith("http"):
                                file_url = urljoin(url, file_url)
                            try:
                                check = self.http_client.get(file_url, timeout=5)
                                for payload in UPLOAD_PAYLOADS.values():
                                    marker = payload.get("marker")
                                    if marker and marker in check.text:
                                        executed = True
                                        break
                            except Exception:
                                pass

            return {"uploaded": uploaded, "executed": executed, "status": resp.status_code}
        except Exception:
            return None
