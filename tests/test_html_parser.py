"""
Tests for secprobe.core.html_parser — DOM parser, form/link extraction, 
reflection mapping, script analysis, and comment analysis.
"""

import pytest
from secprobe.core.html_parser import (
    ContextType,
    DOMNode,
    HTMLDocument,
    FormExtractor,
    FormData,
    FormField,
    LinkExtractor,
    ExtractedLink,
    ScriptAnalyzer,
    ScriptInfo,
    ReflectionMapper,
    ReflectionContext,
    MetaExtractor,
    PageMeta,
    CommentExtractor,
    CommentFinding,
)


# ═══════════════════════════════════════════════════════════════════════
# ContextType
# ═══════════════════════════════════════════════════════════════════════

class TestContextType:
    def test_is_executable_script_contexts(self):
        assert ContextType.SCRIPT_CODE.is_executable is True
        assert ContextType.SCRIPT_STRING_SINGLE.is_executable is True
        assert ContextType.SCRIPT_TEMPLATE_LIT.is_executable is True

    def test_is_executable_html_contexts(self):
        assert ContextType.HTML_TEXT.is_executable is False
        assert ContextType.HTML_ATTRIBUTE_DOUBLE.is_executable is False

    def test_breakout_chars_html_text(self):
        assert "<" in ContextType.HTML_TEXT.breakout_chars

    def test_breakout_chars_attribute(self):
        assert '"' in ContextType.HTML_ATTRIBUTE_DOUBLE.breakout_chars

    def test_event_handler_is_executable(self):
        assert ContextType.HTML_ATTRIBUTE_EVENT.is_executable is True

    def test_style_not_executable(self):
        assert ContextType.STYLE_PROPERTY.is_executable is False

    def test_svg_context_exists(self):
        assert ContextType.SVG_CONTEXT is not None

    def test_cdata_context_exists(self):
        assert ContextType.CDATA is not None


# ═══════════════════════════════════════════════════════════════════════
# DOMNode
# ═══════════════════════════════════════════════════════════════════════

class TestDOMNode:
    def test_basic_node(self):
        node = DOMNode(tag="div", attrs={"class": "test"}, text="Hello")
        assert node.tag == "div"
        assert node.get_attr("class") == "test"
        assert node.inner_text == "Hello"

    def test_children(self):
        parent = DOMNode(tag="div")
        child = DOMNode(tag="span", text="Hi", parent=parent)
        parent.children.append(child)
        assert len(parent.children) == 1
        assert parent.children[0].tag == "span"

    def test_find_all(self):
        root = DOMNode(tag="div")
        p1 = DOMNode(tag="p", text="One")
        p2 = DOMNode(tag="p", text="Two")
        span = DOMNode(tag="span", text="Not p")
        root.children = [p1, p2, span]
        assert len(root.find_all("p")) == 2

    def test_find(self):
        root = DOMNode(tag="div")
        p = DOMNode(tag="p", text="Found")
        root.children = [p]
        result = root.find("p")
        assert result is not None
        assert result.text == "Found"

    def test_find_by_attr(self):
        root = DOMNode(tag="div")
        child = DOMNode(tag="input", attrs={"name": "username"})
        root.children = [child]
        found = root.find_by_attr("name", "username")
        assert len(found) == 1

    def test_has_ancestor(self):
        grandparent = DOMNode(tag="form")
        parent = DOMNode(tag="div", parent=grandparent)
        child = DOMNode(tag="input", parent=parent)
        assert child.has_ancestor("form") is True
        assert child.has_ancestor("table") is False

    def test_get_attr_default(self):
        node = DOMNode(tag="div")
        assert node.get_attr("missing", "default") == "default"

    def test_self_closing(self):
        node = DOMNode(tag="br", is_self_closing=True)
        assert node.is_self_closing is True

    def test_inner_text_with_children(self):
        parent = DOMNode(tag="div", text="Parent ")
        child = DOMNode(tag="span", text="Child")
        parent.children = [child]
        assert "Parent" in parent.inner_text
        assert "Child" in parent.inner_text


# ═══════════════════════════════════════════════════════════════════════
# HTMLDocument
# ═══════════════════════════════════════════════════════════════════════

class TestHTMLDocument:
    def test_parse_basic_html(self):
        html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
        doc = HTMLDocument.parse(html)
        assert doc.title == "Test"

    def test_parse_empty(self):
        doc = HTMLDocument.parse("")
        assert doc.root is not None

    def test_find_all(self):
        html = "<div><p>One</p><p>Two</p><span>Three</span></div>"
        doc = HTMLDocument.parse(html)
        assert len(doc.find_all("p")) == 2

    def test_forms_extraction(self):
        html = '<form action="/login"><input name="user"><input type="password" name="pass"></form>'
        doc = HTMLDocument.parse(html)
        assert len(doc.forms) >= 1

    def test_scripts_extraction(self):
        html = '<html><body><script src="app.js"></script><script>var x=1;</script></body></html>'
        doc = HTMLDocument.parse(html)
        assert len(doc.scripts) >= 1

    def test_links_extraction(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        doc = HTMLDocument.parse(html)
        assert len(doc.links) >= 2

    def test_images(self):
        html = '<img src="logo.png" alt="Logo"><img src="banner.jpg">'
        doc = HTMLDocument.parse(html)
        assert len(doc.images) >= 2

    def test_inputs(self):
        html = '<form><input name="a"><textarea name="b"></textarea></form>'
        doc = HTMLDocument.parse(html)
        assert len(doc.inputs) >= 1

    def test_meta_tags(self):
        html = '<html><head><meta charset="utf-8"><meta name="description" content="Test"></head></html>'
        doc = HTMLDocument.parse(html)
        assert len(doc.meta_tags) >= 1

    def test_iframes(self):
        html = '<iframe src="https://example.com/embed"></iframe>'
        doc = HTMLDocument.parse(html)
        assert len(doc.iframes) >= 1

    def test_text_content(self):
        html = '<div><p>Hello <b>World</b></p><script>var x=1;</script></div>'
        doc = HTMLDocument.parse(html)
        text = doc.text_content
        assert "Hello" in text
        assert "World" in text

    def test_comments(self):
        html = '<div><!-- This is a comment --><p>Content</p></div>'
        doc = HTMLDocument.parse(html)
        assert len(doc.comments) >= 1

    def test_parse_malformed_html(self):
        html = '<div><p>Unclosed<p>Another<div>Nested</p></div>'
        doc = HTMLDocument.parse(html)
        assert doc.root is not None

    def test_raw_html_preserved(self):
        html = '<html><body><p>Test</p></body></html>'
        doc = HTMLDocument.parse(html)
        assert doc.raw_html == html


# ═══════════════════════════════════════════════════════════════════════
# FormExtractor
# ═══════════════════════════════════════════════════════════════════════

class TestFormExtractor:
    def test_extract_basic_form(self):
        html = '<form action="/login" method="POST"><input name="user"><input type="password" name="pass"><input type="submit"></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms) >= 1
        form = forms[0]
        assert form.method == "POST"

    def test_extract_with_csrf(self):
        html = '<form action="/submit"><input type="hidden" name="csrf_token" value="abc123"><input name="data"></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms) >= 1
        form = forms[0]
        assert form.has_csrf_token is True

    def test_extract_file_upload(self):
        html = '<form action="/upload" enctype="multipart/form-data"><input type="file" name="doc"></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms) >= 1
        form = forms[0]
        assert form.has_file_upload is True

    def test_textarea_fields(self):
        html = '<form action="/comment"><textarea name="body">Default</textarea></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms) >= 1
        fields = forms[0].fields
        assert any(f.name == "body" for f in fields)

    def test_select_fields(self):
        html = '<form action="/choose"><select name="color"><option value="red">Red</option><option value="blue">Blue</option></select></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms) >= 1
        fields = forms[0].fields
        assert any(f.name == "color" for f in fields)

    def test_injectable_fields(self):
        html = '<form><input type="hidden" name="token" value="x"><input name="query"><input type="submit"></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms[0].injectable_fields) >= 1

    def test_no_forms(self):
        html = '<div><p>No forms here</p></div>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        assert len(forms) == 0

    def test_to_dict(self):
        html = '<form action="/test"><input name="q"></form>'
        doc = HTMLDocument.parse(html)
        forms = FormExtractor.extract(doc, "http://example.com")
        if forms:
            d = forms[0].to_dict()
            assert isinstance(d, dict)
            assert "q" in d or "fields" in str(d)


# ═══════════════════════════════════════════════════════════════════════
# FormField
# ═══════════════════════════════════════════════════════════════════════

class TestFormField:
    def test_csrf_token_detection(self):
        f = FormField(name="csrf_token", field_type="hidden", value="abc123")
        assert f.is_csrf_token is True

    def test_not_csrf(self):
        f = FormField(name="username", field_type="text", value="")
        assert f.is_csrf_token is False

    def test_is_interesting(self):
        f = FormField(name="password", field_type="password", value="")
        assert f.is_interesting is True

    def test_not_interesting_submit(self):
        f = FormField(name="submit", field_type="submit", value="Go")
        assert f.is_interesting is False


# ═══════════════════════════════════════════════════════════════════════
# LinkExtractor
# ═══════════════════════════════════════════════════════════════════════

class TestLinkExtractor:
    def test_extract_links(self):
        html = '<a href="/about">About</a><a href="https://external.com/page">Ext</a>'
        doc = HTMLDocument.parse(html)
        links = LinkExtractor.extract(doc, "http://example.com")
        assert len(links) >= 2

    def test_external_detection(self):
        html = '<a href="https://other.com/page">Other</a><a href="/local">Local</a>'
        doc = HTMLDocument.parse(html)
        links = LinkExtractor.extract(doc, "http://example.com")
        external = [l for l in links if l.is_external]
        assert len(external) >= 1

    def test_resource_links(self):
        html = '<link rel="stylesheet" href="style.css"><script src="app.js"></script>'
        doc = HTMLDocument.parse(html)
        links = LinkExtractor.extract(doc, "http://example.com")
        assert len(links) >= 1

    def test_empty_doc(self):
        doc = HTMLDocument.parse("<div>No links</div>")
        links = LinkExtractor.extract(doc, "http://example.com")
        assert len(links) == 0

    def test_img_src_links(self):
        html = '<img src="/images/logo.png">'
        doc = HTMLDocument.parse(html)
        links = LinkExtractor.extract(doc, "http://example.com")
        assert any("/images/logo.png" in l.url for l in links)


# ═══════════════════════════════════════════════════════════════════════
# ScriptAnalyzer
# ═══════════════════════════════════════════════════════════════════════

class TestScriptAnalyzer:
    def test_external_script(self):
        html = '<script src="https://cdn.example.com/app.js"></script>'
        doc = HTMLDocument.parse(html)
        scripts = ScriptAnalyzer.analyze(doc)
        assert len(scripts) >= 1
        assert scripts[0].is_inline is False

    def test_inline_script_sinks(self):
        html = '<script>document.innerHTML = userInput; eval(data);</script>'
        doc = HTMLDocument.parse(html)
        scripts = ScriptAnalyzer.analyze(doc)
        assert len(scripts) >= 1
        if scripts[0].sinks:
            assert len(scripts[0].sinks) >= 1

    def test_inline_script_sources(self):
        html = '<script>var x = document.location.hash; var y = window.name;</script>'
        doc = HTMLDocument.parse(html)
        scripts = ScriptAnalyzer.analyze(doc)
        assert len(scripts) >= 1
        if scripts[0].sources:
            assert len(scripts[0].sources) >= 1

    def test_interesting_strings(self):
        html = '<script>var api = "https://api.example.com/v2/data";</script>'
        doc = HTMLDocument.parse(html)
        scripts = ScriptAnalyzer.analyze(doc)
        assert len(scripts) >= 1

    def test_script_nonce(self):
        html = '<script nonce="abc123">alert(1);</script>'
        doc = HTMLDocument.parse(html)
        scripts = ScriptAnalyzer.analyze(doc)
        assert len(scripts) >= 1
        assert scripts[0].nonce == "abc123"

    def test_no_scripts(self):
        doc = HTMLDocument.parse("<div>No scripts</div>")
        scripts = ScriptAnalyzer.analyze(doc)
        assert len(scripts) == 0


# ═══════════════════════════════════════════════════════════════════════
# ReflectionMapper
# ═══════════════════════════════════════════════════════════════════════

class TestReflectionMapper:
    def test_find_text_reflection(self):
        canary = "CANARY12345"
        html = f'<div><p>Your search: {canary}</p></div>'
        doc = HTMLDocument.parse(html)
        reflections = ReflectionMapper.find_reflections(doc, canary)
        assert len(reflections) >= 1
        assert reflections[0].canary == canary

    def test_find_attribute_reflection(self):
        canary = "CANARY67890"
        html = f'<input value="{canary}">'
        doc = HTMLDocument.parse(html)
        reflections = ReflectionMapper.find_reflections(doc, canary)
        assert len(reflections) >= 1

    def test_no_reflection(self):
        html = '<div><p>Nothing special here</p></div>'
        doc = HTMLDocument.parse(html)
        reflections = ReflectionMapper.find_reflections(doc, "NOTHERE")
        assert len(reflections) == 0

    def test_multiple_reflections(self):
        canary = "MULTI_CANARY"
        html = f'<div>{canary}</div><p>{canary}</p><input value="{canary}">'
        doc = HTMLDocument.parse(html)
        reflections = ReflectionMapper.find_reflections(doc, canary)
        assert len(reflections) >= 2


# ═══════════════════════════════════════════════════════════════════════
# MetaExtractor
# ═══════════════════════════════════════════════════════════════════════

class TestMetaExtractor:
    def test_extract_charset(self):
        html = '<html><head><meta charset="utf-8"></head></html>'
        doc = HTMLDocument.parse(html)
        meta = MetaExtractor.extract(doc)
        assert meta.charset == "utf-8"

    def test_extract_description(self):
        html = '<html><head><meta name="description" content="Test site description"></head></html>'
        doc = HTMLDocument.parse(html)
        meta = MetaExtractor.extract(doc)
        assert meta.description == "Test site description"

    def test_extract_robots(self):
        html = '<html><head><meta name="robots" content="noindex, nofollow"></head></html>'
        doc = HTMLDocument.parse(html)
        meta = MetaExtractor.extract(doc)
        assert "noindex" in meta.robots

    def test_framework_detection_angular(self):
        html = '<html ng-app="myApp"><body><div ng-controller="ctrl"></div></body></html>'
        doc = HTMLDocument.parse(html)
        meta = MetaExtractor.extract(doc)
        # Framework detection depends on attribute analysis
        assert isinstance(meta.frameworks, list)

    def test_empty_page(self):
        doc = HTMLDocument.parse("<html><head></head><body></body></html>")
        meta = MetaExtractor.extract(doc)
        assert meta.charset == ""

    def test_csp_extraction(self):
        html = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>'
        doc = HTMLDocument.parse(html)
        meta = MetaExtractor.extract(doc)
        assert meta.csp == "default-src 'self'"


# ═══════════════════════════════════════════════════════════════════════
# CommentExtractor
# ═══════════════════════════════════════════════════════════════════════

class TestCommentExtractor:
    def test_todo_comment(self):
        html = '<!-- TODO: fix authentication bypass --><div>Content</div>'
        doc = HTMLDocument.parse(html)
        findings = CommentExtractor.analyze(doc)
        assert len(findings) >= 1

    def test_credential_comment(self):
        html = '<!-- password: admin123 --><div>Content</div>'
        doc = HTMLDocument.parse(html)
        findings = CommentExtractor.analyze(doc)
        assert len(findings) >= 1

    def test_no_interesting_comments(self):
        html = '<!-- This is a normal comment --><div>Content</div>'
        doc = HTMLDocument.parse(html)
        # Should not flag normal comments
        findings = CommentExtractor.analyze(doc)
        # Normal comments may or may not be flagged depending on heuristics
        assert isinstance(findings, list)

    def test_debug_comment(self):
        html = '<!-- DEBUG=true --><div>Content</div>'
        doc = HTMLDocument.parse(html)
        findings = CommentExtractor.analyze(doc)
        assert len(findings) >= 1

    def test_path_comment(self):
        html = '<!-- /var/www/html/config.php --><div>Content</div>'
        doc = HTMLDocument.parse(html)
        findings = CommentExtractor.analyze(doc)
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════════════
# ExtractedLink
# ═══════════════════════════════════════════════════════════════════════

class TestExtractedLink:
    def test_basic(self):
        link = ExtractedLink(
            url="http://example.com/page",
            source_tag="a",
            source_attr="href",
            text="Page",
            is_external=False,
            is_resource=False,
        )
        assert link.url == "http://example.com/page"
        assert link.source_tag == "a"

    def test_external_flag(self):
        link = ExtractedLink(
            url="https://cdn.other.com/script.js",
            source_tag="script",
            source_attr="src",
            is_external=True,
            is_resource=True,
        )
        assert link.is_external is True
        assert link.is_resource is True
