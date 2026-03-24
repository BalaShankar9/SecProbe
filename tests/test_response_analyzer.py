"""
Tests for secprobe.core.response_analyzer — ResponseModel, DiffEngine,
DynamicDetector, AnomalyDetector, ErrorDetector, ResponseAnalyzerEngine.
"""

import pytest
from secprobe.core.response_analyzer import (
    ContentType,
    ResponseModel,
    DynamicDetector,
    DiffResult,
    DiffEngine,
    AnomalyResult,
    AnomalyDetector,
    ErrorCategory,
    ErrorMatch,
    ErrorDetector,
    AnalysisResult,
    ResponseAnalyzerEngine,
)


# ═══════════════════════════════════════════════════════════════════════
# ContentType
# ═══════════════════════════════════════════════════════════════════════

class TestContentType:
    def test_from_header_html(self):
        assert ContentType.from_header("text/html; charset=utf-8") == ContentType.HTML

    def test_from_header_json(self):
        assert ContentType.from_header("application/json") == ContentType.JSON

    def test_from_header_xml(self):
        assert ContentType.from_header("application/xml") == ContentType.XML

    def test_from_header_javascript(self):
        assert ContentType.from_header("application/javascript") == ContentType.JAVASCRIPT

    def test_from_header_css(self):
        assert ContentType.from_header("text/css") == ContentType.CSS

    def test_from_header_binary(self):
        assert ContentType.from_header("image/png") == ContentType.BINARY
        assert ContentType.from_header("application/octet-stream") == ContentType.BINARY

    def test_from_header_unknown(self):
        assert ContentType.from_header("application/x-custom") == ContentType.UNKNOWN

    def test_detect_html(self):
        assert ContentType.detect("<html><body>Hello</body></html>") == ContentType.HTML

    def test_detect_json(self):
        assert ContentType.detect('{"key": "value"}') == ContentType.JSON
        assert ContentType.detect('[1, 2, 3]') == ContentType.JSON

    def test_detect_empty(self):
        assert ContentType.detect("") == ContentType.EMPTY
        assert ContentType.detect("   ") == ContentType.EMPTY

    def test_detect_plain_text(self):
        assert ContentType.detect("Just some regular text") == ContentType.PLAIN_TEXT

    def test_detect_with_header_override(self):
        assert ContentType.detect("not html", "text/html") == ContentType.HTML

    def test_detect_xml(self):
        assert ContentType.detect('<?xml version="1.0"?>') == ContentType.XML


# ═══════════════════════════════════════════════════════════════════════
# ResponseModel
# ═══════════════════════════════════════════════════════════════════════

class TestResponseModel:
    def test_basic_response(self):
        r = ResponseModel(status_code=200, body="<html><body>OK</body></html>")
        assert r.status_code == 200
        assert r.body_length == len(r.body)
        assert r.content_type == ContentType.HTML

    def test_auto_detect_content_type(self):
        r = ResponseModel(body='{"error": "not found"}')
        assert r.content_type == ContentType.JSON

    def test_content_type_from_header(self):
        r = ResponseModel(
            body="<data>test</data>",
            headers={"content-type": "application/xml"},
        )
        assert r.content_type == ContentType.XML

    def test_body_hash(self):
        r = ResponseModel(body="test body")
        assert len(r.body_hash) == 32  # MD5 hex

    def test_body_hash_consistent(self):
        r = ResponseModel(body="same content")
        assert r.body_hash == r.body_hash

    def test_is_error(self):
        assert ResponseModel(status_code=404).is_error is True
        assert ResponseModel(status_code=500).is_error is True
        assert ResponseModel(status_code=200).is_error is False

    def test_is_redirect(self):
        assert ResponseModel(status_code=301).is_redirect is True
        assert ResponseModel(status_code=302).is_redirect is True
        assert ResponseModel(status_code=200).is_redirect is False

    def test_is_success(self):
        assert ResponseModel(status_code=200).is_success is True
        assert ResponseModel(status_code=201).is_success is True
        assert ResponseModel(status_code=404).is_success is False

    def test_text_content_html(self):
        r = ResponseModel(body="<html><body><p>Hello World</p><script>x=1</script></body></html>")
        assert "Hello World" in r.text_content

    def test_text_content_plain(self):
        r = ResponseModel(body="plain text", headers={"content-type": "text/plain"})
        assert r.text_content == "plain text"

    def test_empty_body(self):
        r = ResponseModel(body="")
        assert r.content_type == ContentType.EMPTY
        assert r.body_length == 0

    def test_parsed_html(self):
        r = ResponseModel(body="<html><head><title>Test</title></head><body></body></html>")
        doc = r.parsed_html
        assert doc.title == "Test"


# ═══════════════════════════════════════════════════════════════════════
# DynamicDetector
# ═══════════════════════════════════════════════════════════════════════

class TestDynamicDetector:
    def test_strip_timestamps(self):
        dd = DynamicDetector()
        text = "Generated at 2024-01-15T10:30:00Z by server"
        stripped = dd.strip_dynamic(text)
        assert "2024-01-15" not in stripped

    def test_strip_uuid(self):
        dd = DynamicDetector()
        text = 'Session: 550e8400-e29b-41d4-a716-446655440000'
        stripped = dd.strip_dynamic(text)
        assert "550e8400" not in stripped

    def test_strip_csrf_tokens(self):
        dd = DynamicDetector()
        text = 'csrf_token="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"'
        stripped = dd.strip_dynamic(text)
        assert "a1b2c3d4e5f6" not in stripped

    def test_strip_unix_timestamp(self):
        dd = DynamicDetector()
        text = "Cache bust: 1705312200"
        stripped = dd.strip_dynamic(text)
        assert "1705312200" not in stripped

    def test_learn_from_baselines(self):
        dd = DynamicDetector()
        base1 = "Hello World count=12345"
        base2 = "Hello World count=67890"
        dd.learn_from_baselines([base1, base2])
        assert dd.pattern_count > len(dd.DYNAMIC_PATTERNS)

    def test_learn_needs_multiple(self):
        dd = DynamicDetector()
        initial = dd.pattern_count
        dd.learn_from_baselines(["only one"])
        assert dd.pattern_count == initial

    def test_preserve_non_dynamic(self):
        dd = DynamicDetector()
        text = "This is normal static content"
        assert dd.strip_dynamic(text) == text


# ═══════════════════════════════════════════════════════════════════════
# DiffEngine
# ═══════════════════════════════════════════════════════════════════════

class TestDiffEngine:
    def test_identical_responses(self):
        engine = DiffEngine()
        r = ResponseModel(status_code=200, body="Same content")
        result = engine.compare(r, r)
        assert result.similarity == 1.0
        assert result.status_changed is False
        assert result.is_significant is False

    def test_status_code_change(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="OK")
        test = ResponseModel(status_code=500, body="Error")
        result = engine.compare(base, test)
        assert result.status_changed is True
        assert result.is_significant is True

    def test_body_difference(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="Hello World")
        test = ResponseModel(status_code=200, body="Hello Error World SQL syntax")
        result = engine.compare(base, test)
        assert result.similarity < 1.0

    def test_size_delta(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="short")
        test = ResponseModel(status_code=200, body="much longer content here that differs significantly")
        result = engine.compare(base, test)
        assert result.size_delta > 0
        assert result.size_ratio > 1.0

    def test_header_changes(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="OK", headers={"X-Custom": "value1"})
        test = ResponseModel(status_code=200, body="OK", headers={"X-Custom": "value2"})
        result = engine.compare(base, test)
        assert "X-Custom" in result.changed_headers

    def test_skip_volatile_headers(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="OK", headers={"Date": "Mon"})
        test = ResponseModel(status_code=200, body="OK", headers={"Date": "Tue"})
        result = engine.compare(base, test)
        assert "Date" not in result.changed_headers

    def test_content_type_change(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="<html><body>OK</body></html>")
        test = ResponseModel(status_code=200, body='{"error": "oops"}')
        result = engine.compare(base, test)
        assert result.content_type_changed is True

    def test_empty_responses(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="")
        test = ResponseModel(status_code=200, body="")
        result = engine.compare(base, test)
        assert result.similarity == 1.0

    def test_added_removed_text(self):
        engine = DiffEngine()
        base = ResponseModel(status_code=200, body="Hello World from the server")
        test = ResponseModel(status_code=200, body="Hello SQL Error from the database")
        result = engine.compare(base, test)
        assert len(result.added_text) > 0 or len(result.removed_text) > 0

    def test_json_similarity(self):
        engine = DiffEngine()
        base = ResponseModel(
            status_code=200,
            body='{"name": "Alice", "age": 30}',
            headers={"content-type": "application/json"},
        )
        test = ResponseModel(
            status_code=200,
            body='{"name": "Bob", "age": 30}',
            headers={"content-type": "application/json"},
        )
        result = engine.compare(base, test)
        # name differs, age same → partial similarity
        assert 0.3 < result.similarity < 1.0


# ═══════════════════════════════════════════════════════════════════════
# AnomalyDetector
# ═══════════════════════════════════════════════════════════════════════

class TestAnomalyDetector:
    def test_no_baselines(self):
        ad = AnomalyDetector()
        result = ad.analyze(ResponseModel(status_code=200, body="test"))
        assert result.is_anomalous is False

    def test_few_baselines(self):
        ad = AnomalyDetector()
        ad.add_baseline(ResponseModel(status_code=200, body="ok"))
        result = ad.analyze(ResponseModel(status_code=500, body="error"))
        # Only 1 baseline, needs at least 2
        assert result.is_anomalous is False

    def test_status_anomaly(self):
        ad = AnomalyDetector()
        for _ in range(5):
            ad.add_baseline(ResponseModel(status_code=200, body="x" * 100))
        result = ad.analyze(ResponseModel(status_code=500, body="x" * 100))
        assert result.status_anomaly is True

    def test_size_anomaly(self):
        ad = AnomalyDetector()
        for _ in range(5):
            ad.add_baseline(ResponseModel(status_code=200, body="x" * 100))
        # Much larger response
        result = ad.analyze(ResponseModel(status_code=200, body="x" * 10000))
        assert result.size_anomaly is True

    def test_normal_response(self):
        ad = AnomalyDetector()
        body = "Hello World response"
        for _ in range(5):
            ad.add_baseline(ResponseModel(status_code=200, body=body))
        result = ad.analyze(ResponseModel(status_code=200, body=body))
        assert result.is_anomalous is False

    def test_content_anomaly(self):
        ad = AnomalyDetector()
        for i in range(3):
            ad.add_baseline(ResponseModel(status_code=200, body="standard response"))
        result = ad.analyze(ResponseModel(status_code=200, body="completely different"))
        assert result.content_anomaly is True

    def test_baseline_count(self):
        ad = AnomalyDetector()
        assert ad.baseline_count == 0
        ad.add_baseline(ResponseModel(status_code=200, body="x"))
        assert ad.baseline_count == 1


# ═══════════════════════════════════════════════════════════════════════
# ErrorDetector
# ═══════════════════════════════════════════════════════════════════════

class TestErrorDetector:
    def test_mysql_error(self):
        ed = ErrorDetector()
        body = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert matches[0].category == ErrorCategory.SQL_ERROR
        assert matches[0].technology == "MySQL"

    def test_postgresql_error(self):
        ed = ErrorDetector()
        body = 'ERROR:  syntax error at or near "SELECT"'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.technology == "PostgreSQL" for m in matches)

    def test_mssql_error(self):
        ed = ErrorDetector()
        body = 'Microsoft OLE DB Provider for ODBC Drivers error something'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.technology == "MSSQL" for m in matches)

    def test_oracle_error(self):
        ed = ErrorDetector()
        body = 'ORA-01756: quoted string not properly terminated'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.technology == "Oracle" for m in matches)

    def test_sqlite_error(self):
        ed = ErrorDetector()
        body = 'sqlite3.OperationalError: near "FROM": syntax error'
        matches = ed.detect(body)
        assert len(matches) >= 1

    def test_python_stack_trace(self):
        ed = ErrorDetector()
        body = 'Traceback (most recent call last):\n  File "app.py", line 10'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.STACK_TRACE for m in matches)

    def test_php_error(self):
        ed = ErrorDetector()
        body = 'Fatal error: Call to undefined in /var/www/app.php on line 42'
        matches = ed.detect(body)
        assert len(matches) >= 1

    def test_java_stack_trace(self):
        ed = ErrorDetector()
        body = 'Exception in thread "main" java.lang.Error at com.app.Main(Main.java:15)'
        matches = ed.detect(body)
        assert len(matches) >= 1

    def test_template_error_jinja(self):
        ed = ErrorDetector()
        body = 'jinja2.exceptions.UndefinedError: "name" is undefined'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.TEMPLATE_ERROR for m in matches)

    def test_command_error(self):
        ed = ErrorDetector()
        body = 'sh: 1: whoami: not found'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.COMMAND_ERROR for m in matches)

    def test_file_error(self):
        ed = ErrorDetector()
        body = 'No such file or directory: /etc/passwd'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.FILE_ERROR for m in matches)

    def test_debug_info(self):
        ed = ErrorDetector()
        body = 'FLASK_DEBUG is set to true. Django settings.py exposed. DEBUG = True'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.DEBUG_INFO for m in matches)

    def test_no_errors(self):
        ed = ErrorDetector()
        body = '<html><body><h1>Welcome</h1><p>Normal page</p></body></html>'
        matches = ed.detect(body)
        assert len(matches) == 0

    def test_has_errors_quick(self):
        ed = ErrorDetector()
        assert ed.has_errors("SQL syntax error MySQL") is True
        assert ed.has_errors("Normal page content") is False

    def test_detect_technology(self):
        ed = ErrorDetector()
        body = 'Traceback (most recent call last):\n  File "app.py" and MySQL error SQL syntax'
        techs = ed.detect_technology(body)
        assert "Python" in techs or "MySQL" in techs

    def test_empty_body(self):
        ed = ErrorDetector()
        assert ed.detect("") == []
        assert ed.has_errors("") is False

    def test_mongodb_error(self):
        ed = ErrorDetector()
        body = 'MongoError: query failed'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.NOSQL_ERROR for m in matches)

    def test_xml_error(self):
        ed = ErrorDetector()
        body = 'XML Parsing Error: not well-formed'
        matches = ed.detect(body)
        assert len(matches) >= 1
        assert any(m.category == ErrorCategory.XML_ERROR for m in matches)


# ═══════════════════════════════════════════════════════════════════════
# AnalysisResult
# ═══════════════════════════════════════════════════════════════════════

class TestAnalysisResult:
    def test_not_interesting_empty(self):
        result = AnalysisResult()
        assert result.is_interesting is False

    def test_interesting_with_errors(self):
        result = AnalysisResult(errors=[
            ErrorMatch(ErrorCategory.SQL_ERROR, "test", "SQL error", "MySQL")
        ])
        assert result.is_interesting is True

    def test_interesting_with_anomaly(self):
        result = AnalysisResult(anomaly=AnomalyResult(is_anomalous=True))
        assert result.is_interesting is True

    def test_interesting_with_diff(self):
        result = AnalysisResult(diff=DiffResult(status_changed=True))
        assert result.is_interesting is True


# ═══════════════════════════════════════════════════════════════════════
# ResponseAnalyzerEngine
# ═══════════════════════════════════════════════════════════════════════

class TestResponseAnalyzerEngine:
    def test_basic_analysis(self):
        engine = ResponseAnalyzerEngine()
        result = engine.analyze(ResponseModel(status_code=200, body="<p>Hello</p>"))
        assert isinstance(result, AnalysisResult)

    def test_with_baselines(self):
        engine = ResponseAnalyzerEngine()
        baseline = ResponseModel(status_code=200, body="Normal response body")
        engine.add_baseline(baseline)
        engine.add_baseline(ResponseModel(status_code=200, body="Normal response body"))
        engine.learn_baselines()

        result = engine.analyze(ResponseModel(status_code=500, body="SQL error MySQL"))
        assert result.diff is not None
        assert result.diff.status_changed is True

    def test_error_detection(self):
        engine = ResponseAnalyzerEngine()
        result = engine.analyze(ResponseModel(
            status_code=500,
            body="Traceback (most recent call last): File app.py",
        ))
        assert len(result.errors) >= 1
        assert len(result.technologies) >= 1

    def test_anomaly_detection(self):
        engine = ResponseAnalyzerEngine()
        for _ in range(5):
            engine.add_baseline(ResponseModel(status_code=200, body="x" * 100))

        result = engine.analyze(ResponseModel(status_code=200, body="x" * 10000))
        assert result.anomaly is not None
        assert result.anomaly.size_anomaly is True

    def test_quick_check_error(self):
        engine = ResponseAnalyzerEngine()
        assert engine.quick_check(ResponseModel(
            body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        )) is True

    def test_quick_check_status_diff(self):
        engine = ResponseAnalyzerEngine()
        engine.add_baseline(ResponseModel(status_code=200, body="OK"))
        assert engine.quick_check(ResponseModel(status_code=500, body="Error")) is True

    def test_quick_check_normal(self):
        engine = ResponseAnalyzerEngine()
        engine.add_baseline(ResponseModel(status_code=200, body="Normal"))
        assert engine.quick_check(ResponseModel(status_code=200, body="Normal")) is False

    def test_baseline_count(self):
        engine = ResponseAnalyzerEngine()
        assert engine.baseline_count == 0
        engine.add_baseline(ResponseModel(status_code=200, body="x"))
        assert engine.baseline_count == 1

    def test_compare_with_specific_baseline(self):
        engine = ResponseAnalyzerEngine()
        base1 = ResponseModel(status_code=200, body="Response A")
        base2 = ResponseModel(status_code=200, body="Response B")
        engine.add_baseline(base1)

        result = engine.analyze(
            ResponseModel(status_code=200, body="Response C"),
            compare_baseline=base2,
        )
        assert result.diff is not None
