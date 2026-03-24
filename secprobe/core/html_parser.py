"""
HTML Parser — Proper DOM-aware parsing for security analysis.

Replaces regex-based HTML parsing throughout SecProbe with a real parser
built on Python's html.parser (zero external dependencies).

Capabilities:
  1. HTMLDocument    — Full DOM tree with tag/attribute/text nodes
  2. FormExtractor   — Extracts forms, inputs, actions, CSRF tokens
  3. LinkExtractor   — Extracts all links (href, src, action, data-*, JS)
  4. ScriptAnalyzer  — Extracts inline/external scripts, finds sinks/sources
  5. ReflectionMapper— Finds exact reflection context of a canary in parsed DOM
  6. ContextType      — Enumeration of HTML contexts for XSS payload selection
  7. MetaExtractor   — Extracts meta tags, CSP, charset, redirects
  8. CommentExtractor— Extracts HTML comments (often leak sensitive info)

Why this matters:
  - Regex can't reliably determine if a canary is inside a <script> tag,
    an HTML attribute, or a comment — context-aware payloads need a real parser.
  - Form extraction via regex misses multi-line forms, nested elements, etc.
  - Script analysis needs to understand tag boundaries to avoid false matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse


# ═══════════════════════════════════════════════════════════════════════
# Context Types — Where a reflection lands in the DOM
# ═══════════════════════════════════════════════════════════════════════

class ContextType(Enum):
    """HTML context where reflected input appears — drives payload selection."""
    HTML_TEXT = auto()            # Between tags: <div>REFLECTED</div>
    HTML_ATTRIBUTE_SINGLE = auto()  # In single-quoted attr: <div title='REFLECTED'>
    HTML_ATTRIBUTE_DOUBLE = auto()  # In double-quoted attr: <div title="REFLECTED">
    HTML_ATTRIBUTE_UNQUOTED = auto() # Unquoted attr: <div title=REFLECTED>
    HTML_ATTRIBUTE_HREF = auto()    # In href/src: <a href="REFLECTED">
    HTML_ATTRIBUTE_EVENT = auto()   # In event handler: <div onclick="REFLECTED">
    HTML_ATTRIBUTE_STYLE = auto()   # In style attr: <div style="REFLECTED">
    SCRIPT_STRING_SINGLE = auto()   # JS single-quoted: var x='REFLECTED'
    SCRIPT_STRING_DOUBLE = auto()   # JS double-quoted: var x="REFLECTED"
    SCRIPT_TEMPLATE_LIT = auto()    # JS template literal: var x=`REFLECTED`
    SCRIPT_CODE = auto()            # Bare JS code: var x=REFLECTED
    STYLE_PROPERTY = auto()         # CSS property: color: REFLECTED
    STYLE_URL = auto()              # CSS url(): url(REFLECTED)
    HTML_COMMENT = auto()           # Inside <!-- REFLECTED -->
    SVG_CONTEXT = auto()            # Inside <svg> element
    MATH_CONTEXT = auto()           # Inside <math> element
    CDATA = auto()                  # Inside <![CDATA[ REFLECTED ]]>
    UNKNOWN = auto()

    @property
    def is_executable(self) -> bool:
        """Whether this context can directly execute JavaScript."""
        return self in (
            ContextType.HTML_ATTRIBUTE_EVENT,
            ContextType.HTML_ATTRIBUTE_HREF,
            ContextType.SCRIPT_STRING_SINGLE,
            ContextType.SCRIPT_STRING_DOUBLE,
            ContextType.SCRIPT_TEMPLATE_LIT,
            ContextType.SCRIPT_CODE,
        )

    @property
    def breakout_chars(self) -> str:
        """Characters needed to break out of this context."""
        return {
            ContextType.HTML_TEXT: "<",
            ContextType.HTML_ATTRIBUTE_SINGLE: "'",
            ContextType.HTML_ATTRIBUTE_DOUBLE: '"',
            ContextType.HTML_ATTRIBUTE_UNQUOTED: " >",
            ContextType.HTML_ATTRIBUTE_HREF: "",
            ContextType.HTML_ATTRIBUTE_EVENT: "",
            ContextType.SCRIPT_STRING_SINGLE: "'",
            ContextType.SCRIPT_STRING_DOUBLE: '"',
            ContextType.SCRIPT_TEMPLATE_LIT: "`",
            ContextType.SCRIPT_CODE: "",
            ContextType.HTML_COMMENT: "-->",
        }.get(self, "")


# ═══════════════════════════════════════════════════════════════════════
# DOM Node Types
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class DOMNode:
    """A node in the parsed DOM tree."""
    tag: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    text: str = ""
    children: list[DOMNode] = field(default_factory=list)
    parent: Optional[DOMNode] = field(default=None, repr=False)
    is_self_closing: bool = False
    source_line: int = 0
    source_offset: int = 0

    @property
    def inner_text(self) -> str:
        """Get all text content including children."""
        parts = []
        if self.text:
            parts.append(self.text)
        for child in self.children:
            parts.append(child.inner_text)
        return " ".join(parts)

    @property
    def inner_html(self) -> str:
        """Reconstruct inner HTML (approximation)."""
        parts = []
        if self.text:
            parts.append(self.text)
        for child in self.children:
            parts.append(child.outer_html)
        return "".join(parts)

    @property
    def outer_html(self) -> str:
        """Reconstruct full HTML of this element."""
        if not self.tag:
            return self.text
        attrs_str = ""
        for k, v in self.attrs.items():
            if v is None:
                attrs_str += f" {k}"
            else:
                attrs_str += f' {k}="{v}"'
        if self.is_self_closing:
            return f"<{self.tag}{attrs_str}/>"
        return f"<{self.tag}{attrs_str}>{self.inner_html}</{self.tag}>"

    def get_attr(self, name: str, default: str = "") -> str:
        """Get attribute value, case-insensitive."""
        return self.attrs.get(name.lower(), default)

    def find_all(self, tag: str) -> list[DOMNode]:
        """Find all descendant elements with the given tag name."""
        results = []
        tag_lower = tag.lower()
        for child in self.children:
            if child.tag.lower() == tag_lower:
                results.append(child)
            results.extend(child.find_all(tag))
        return results

    def find(self, tag: str) -> Optional[DOMNode]:
        """Find first descendant with the given tag."""
        matches = self.find_all(tag)
        return matches[0] if matches else None

    def find_by_attr(self, attr: str, value: str) -> list[DOMNode]:
        """Find all descendants with a specific attribute value."""
        results = []
        for child in self.children:
            if child.get_attr(attr) == value:
                results.append(child)
            results.extend(child.find_by_attr(attr, value))
        return results

    def has_ancestor(self, tag: str) -> bool:
        """Check if any ancestor has the given tag."""
        node = self.parent
        tag_lower = tag.lower()
        while node:
            if node.tag.lower() == tag_lower:
                return True
            node = node.parent
        return False


# ═══════════════════════════════════════════════════════════════════════
# Core HTML Parser — Builds a DOM tree
# ═══════════════════════════════════════════════════════════════════════

SELF_CLOSING_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})

RAWTEXT_TAGS = frozenset({"script", "style", "textarea", "title"})


class _DOMBuilder(HTMLParser):
    """Internal parser that builds a DOMNode tree."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.root = DOMNode(tag="document")
        self._stack: list[DOMNode] = [self.root]
        self.comments: list[str] = []
        self.errors: list[str] = []

    @property
    def _current(self) -> DOMNode:
        return self._stack[-1]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        node = DOMNode(
            tag=tag.lower(),
            attrs={k.lower(): (v if v is not None else "") for k, v in attrs},
            is_self_closing=tag.lower() in SELF_CLOSING_TAGS,
            source_line=self.getpos()[0],
            source_offset=self.getpos()[1],
        )
        node.parent = self._current
        self._current.children.append(node)
        if tag.lower() not in SELF_CLOSING_TAGS:
            self._stack.append(node)

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        # Find matching open tag (may need to skip mis-nested tags)
        for i in range(len(self._stack) - 1, 0, -1):
            if self._stack[i].tag == tag_lower:
                self._stack = self._stack[: i]
                break

    def handle_data(self, data: str):
        if data.strip():
            text_node = DOMNode(text=data, parent=self._current)
            self._current.children.append(text_node)

    def handle_comment(self, data: str):
        self.comments.append(data)
        comment_node = DOMNode(tag="!comment", text=data, parent=self._current)
        self._current.children.append(comment_node)

    def handle_entityref(self, name: str):
        self.handle_data(f"&{name};")

    def handle_charref(self, name: str):
        self.handle_data(f"&#{name};")

    def error(self, message: str):
        self.errors.append(message)


# ═══════════════════════════════════════════════════════════════════════
# HTMLDocument — The main parsed document interface
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class HTMLDocument:
    """
    Parsed HTML document with full DOM access.

    Usage:
        doc = HTMLDocument.parse("<html><body><h1>Test</h1></body></html>")
        headings = doc.find_all("h1")
        forms = doc.forms
        scripts = doc.scripts
        comments = doc.comments
    """
    root: DOMNode = field(default_factory=lambda: DOMNode(tag="document"))
    comments: list[str] = field(default_factory=list)
    raw_html: str = ""
    parse_errors: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, html: str) -> HTMLDocument:
        """Parse an HTML string into a structured document."""
        builder = _DOMBuilder()
        try:
            builder.feed(html)
        except Exception:
            pass  # Best-effort parsing — security tool must be resilient
        return cls(
            root=builder.root,
            comments=builder.comments,
            raw_html=html,
            parse_errors=builder.errors,
        )

    # ── Convenience Accessors ────────────────────────────────────

    def find_all(self, tag: str) -> list[DOMNode]:
        """Find all elements with the given tag."""
        return self.root.find_all(tag)

    def find(self, tag: str) -> Optional[DOMNode]:
        """Find first element with the given tag."""
        return self.root.find(tag)

    @property
    def title(self) -> str:
        """Page title text."""
        node = self.find("title")
        return node.inner_text.strip() if node else ""

    @property
    def forms(self) -> list[DOMNode]:
        return self.find_all("form")

    @property
    def scripts(self) -> list[DOMNode]:
        return self.find_all("script")

    @property
    def links(self) -> list[DOMNode]:
        return self.find_all("a")

    @property
    def images(self) -> list[DOMNode]:
        return self.find_all("img")

    @property
    def inputs(self) -> list[DOMNode]:
        return self.find_all("input")

    @property
    def meta_tags(self) -> list[DOMNode]:
        return self.find_all("meta")

    @property
    def iframes(self) -> list[DOMNode]:
        return self.find_all("iframe")

    @property
    def text_content(self) -> str:
        """Get all visible text content."""
        return self.root.inner_text


# ═══════════════════════════════════════════════════════════════════════
# FormExtractor — Structured form data extraction
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class FormField:
    """A single form field with type, name, value."""
    name: str
    field_type: str = "text"      # text, hidden, password, email, checkbox, etc.
    value: str = ""
    required: bool = False
    options: list[str] = field(default_factory=list)  # For <select>/<datalist>

    @property
    def is_csrf_token(self) -> bool:
        """Heuristic: does this look like a CSRF token?"""
        csrf_patterns = [
            "csrf", "token", "_token", "xsrf", "authenticity",
            "nonce", "__requestverificationtoken", "antiforgery",
        ]
        name_lower = self.name.lower()
        return any(p in name_lower for p in csrf_patterns)

    @property
    def is_interesting(self) -> bool:
        """Is this field likely to be security-relevant for testing?"""
        if self.is_csrf_token:
            return False  # Don't fuzz CSRF tokens
        interesting_types = {"text", "search", "url", "email", "hidden", "password", ""}
        return self.field_type.lower() in interesting_types


@dataclass
class FormData:
    """Structured representation of an HTML form."""
    action: str = ""
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)
    has_file_upload: bool = False
    has_csrf_token: bool = False
    id: str = ""
    name: str = ""

    @property
    def injectable_fields(self) -> list[FormField]:
        """Fields suitable for injection testing."""
        return [f for f in self.fields if f.is_interesting]

    @property
    def csrf_token_field(self) -> Optional[FormField]:
        """Return the CSRF token field, if any."""
        for f in self.fields:
            if f.is_csrf_token:
                return f
        return None

    def to_dict(self) -> dict[str, str]:
        """Convert to a dict suitable for requests.post(data=...)."""
        return {f.name: f.value for f in self.fields if f.name}


class FormExtractor:
    """Extract structured form data from parsed HTML."""

    @staticmethod
    def extract(doc: HTMLDocument, base_url: str = "") -> list[FormData]:
        """Extract all forms with their fields."""
        results = []
        for form_node in doc.forms:
            form = FormData(
                action=FormExtractor._resolve_url(
                    form_node.get_attr("action", ""), base_url
                ),
                method=form_node.get_attr("method", "GET").upper(),
                enctype=form_node.get_attr(
                    "enctype", "application/x-www-form-urlencoded"
                ),
                id=form_node.get_attr("id"),
                name=form_node.get_attr("name"),
            )

            # Extract <input> fields
            for inp in form_node.find_all("input"):
                f = FormField(
                    name=inp.get_attr("name"),
                    field_type=inp.get_attr("type", "text"),
                    value=inp.get_attr("value"),
                    required="required" in inp.attrs,
                )
                if f.name:
                    form.fields.append(f)
                    if f.field_type.lower() == "file":
                        form.has_file_upload = True

            # Extract <textarea>
            for ta in form_node.find_all("textarea"):
                f = FormField(
                    name=ta.get_attr("name"),
                    field_type="textarea",
                    value=ta.inner_text,
                    required="required" in ta.attrs,
                )
                if f.name:
                    form.fields.append(f)

            # Extract <select>
            for sel in form_node.find_all("select"):
                options = [
                    opt.get_attr("value", opt.inner_text)
                    for opt in sel.find_all("option")
                ]
                f = FormField(
                    name=sel.get_attr("name"),
                    field_type="select",
                    value=options[0] if options else "",
                    options=options,
                )
                if f.name:
                    form.fields.append(f)

            # Check for CSRF token
            form.has_csrf_token = any(f.is_csrf_token for f in form.fields)
            results.append(form)

        return results

    @staticmethod
    def _resolve_url(url: str, base_url: str) -> str:
        if not url or not base_url:
            return url
        return urljoin(base_url, url)


# ═══════════════════════════════════════════════════════════════════════
# LinkExtractor — All URLs from the document
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ExtractedLink:
    """A link extracted from HTML with context."""
    url: str
    source_tag: str = ""         # a, img, script, link, iframe, etc.
    source_attr: str = ""        # href, src, action, data-url, etc.
    text: str = ""               # Anchor text
    is_external: bool = False
    is_resource: bool = False    # CSS, JS, image, font


class LinkExtractor:
    """Extract all URLs from a parsed HTML document."""

    # Tags and their URL-bearing attributes
    URL_ATTRS = {
        "a": ["href"],
        "img": ["src", "srcset", "data-src", "data-lazy-src"],
        "script": ["src"],
        "link": ["href"],
        "iframe": ["src"],
        "frame": ["src"],
        "form": ["action"],
        "video": ["src", "poster"],
        "audio": ["src"],
        "source": ["src", "srcset"],
        "embed": ["src"],
        "object": ["data"],
        "area": ["href"],
        "base": ["href"],
        "meta": ["content"],  # Only for http-equiv="refresh"
    }

    RESOURCE_TAGS = frozenset({"img", "script", "link", "video", "audio",
                                "source", "embed", "object"})

    @classmethod
    def extract(cls, doc: HTMLDocument, base_url: str = "") -> list[ExtractedLink]:
        """Extract all links from the document."""
        links = []
        base_domain = urlparse(base_url).netloc if base_url else ""

        for tag_name, attrs in cls.URL_ATTRS.items():
            for node in doc.find_all(tag_name):
                for attr_name in attrs:
                    raw_url = node.get_attr(attr_name)
                    if not raw_url:
                        continue

                    # Skip non-URLs in meta content
                    if tag_name == "meta" and attr_name == "content":
                        if "url=" in raw_url.lower():
                            raw_url = raw_url.split("url=", 1)[-1].strip("' \"")
                        else:
                            continue

                    # Handle srcset (may contain multiple URLs)
                    if attr_name == "srcset":
                        for part in raw_url.split(","):
                            url = part.strip().split()[0] if part.strip() else ""
                            if url:
                                links.append(cls._make_link(
                                    url, tag_name, attr_name, node, base_url, base_domain
                                ))
                        continue

                    # Skip javascript: and data: URIs for link collection
                    # (but note them — they may be security-relevant)
                    if raw_url.strip().lower().startswith(("data:", "mailto:", "tel:")):
                        continue

                    resolved = urljoin(base_url, raw_url) if base_url else raw_url
                    links.append(cls._make_link(
                        resolved, tag_name, attr_name, node, base_url, base_domain
                    ))

        # Also extract URLs from inline JS (common in SPAs)
        for script in doc.scripts:
            if not script.get_attr("src"):  # inline script
                js_urls = cls._extract_js_urls(script.inner_text, base_url)
                for url in js_urls:
                    links.append(ExtractedLink(
                        url=url, source_tag="script", source_attr="inline",
                    ))

        return links

    @classmethod
    def _make_link(cls, url: str, tag: str, attr: str, node: DOMNode,
                   base_url: str, base_domain: str) -> ExtractedLink:
        parsed = urlparse(url)
        is_ext = bool(parsed.netloc and parsed.netloc != base_domain)
        return ExtractedLink(
            url=url,
            source_tag=tag,
            source_attr=attr,
            text=node.inner_text.strip()[:100] if tag == "a" else "",
            is_external=is_ext,
            is_resource=tag in cls.RESOURCE_TAGS,
        )

    @staticmethod
    def _extract_js_urls(js_code: str, base_url: str = "") -> list[str]:
        """Extract URL-like strings from JavaScript code."""
        urls = set()
        # Match quoted strings that look like URLs or paths
        for match in re.finditer(
            r'''(?:["'])((?:https?://|/)[^\s"'<>]{3,200})(?:["'])''',
            js_code,
        ):
            url = match.group(1)
            if base_url and url.startswith("/"):
                url = urljoin(base_url, url)
            urls.add(url)
        return list(urls)


# ═══════════════════════════════════════════════════════════════════════
# ScriptAnalyzer — JavaScript security analysis
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ScriptInfo:
    """Information about a script element."""
    src: str = ""
    is_inline: bool = False
    content: str = ""
    nonce: str = ""
    integrity: str = ""
    crossorigin: str = ""
    sinks: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)


class ScriptAnalyzer:
    """Analyze scripts for DOM XSS sinks, sources, and sensitive patterns."""

    # DOM XSS sinks (dangerous JS functions)
    SINKS = [
        (r"document\.write\s*\(", "document.write"),
        (r"document\.writeln\s*\(", "document.writeln"),
        (r"\.innerHTML\s*=", ".innerHTML"),
        (r"\.outerHTML\s*=", ".outerHTML"),
        (r"\.insertAdjacentHTML\s*\(", ".insertAdjacentHTML"),
        (r"eval\s*\(", "eval()"),
        (r"Function\s*\(", "Function()"),
        (r"setTimeout\s*\(\s*[\"'`]", "setTimeout(string)"),
        (r"setInterval\s*\(\s*[\"'`]", "setInterval(string)"),
        (r"document\.location\s*=", "document.location"),
        (r"window\.location\s*=", "window.location"),
        (r"location\.assign\s*\(", "location.assign"),
        (r"location\.replace\s*\(", "location.replace"),
        (r"\.src\s*=", ".src assignment"),
        (r"\.href\s*=", ".href assignment"),
        (r"\.action\s*=", ".action assignment"),
        (r"jQuery\.html\s*\(|\.html\s*\(", "jQuery.html()"),
        (r"\$\s*\(\s*[\"'`].*[\"'`]\s*\)\.html\s*\(", "jQuery selector.html()"),
        (r"\.append\s*\(", ".append()"),
        (r"\.prepend\s*\(", ".prepend()"),
        (r"\.after\s*\(", ".after()"),
        (r"\.before\s*\(", ".before()"),
        (r"\.replaceWith\s*\(", ".replaceWith()"),
        (r"\.wrapAll\s*\(", ".wrapAll()"),
    ]

    # DOM XSS sources (user-controllable input)
    SOURCES = [
        (r"document\.URL\b", "document.URL"),
        (r"document\.documentURI\b", "document.documentURI"),
        (r"document\.referrer\b", "document.referrer"),
        (r"document\.cookie\b", "document.cookie"),
        (r"location\.hash\b", "location.hash"),
        (r"location\.search\b", "location.search"),
        (r"location\.href\b", "location.href"),
        (r"location\.pathname\b", "location.pathname"),
        (r"window\.name\b", "window.name"),
        (r"window\.postMessage\b", "postMessage"),
        (r"localStorage\.", "localStorage"),
        (r"sessionStorage\.", "sessionStorage"),
        (r"URLSearchParams\b", "URLSearchParams"),
        (r"\.getResponseHeader\s*\(", "getResponseHeader"),
        (r"history\.pushState\b", "history.pushState"),
        (r"history\.replaceState\b", "history.replaceState"),
    ]

    # Interesting patterns (API keys, secrets, endpoints)
    INTERESTING = [
        (r"""(?:api[_-]?key|apikey|api_secret|auth_token|access_token|secret_key)\s*[:=]\s*["'`]([^"'`]{8,})["'`]""", "API key/secret"),
        (r"""(?:password|passwd|pwd)\s*[:=]\s*["'`]([^"'`]+)["'`]""", "Password"),
        (r"""(?:https?://[^\s"'`<>]{20,})""", "URL endpoint"),
        (r"""(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*)""", "Bearer token"),
        (r"""(?:eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})""", "JWT token"),
        (r"""(?:AWS[A-Z0-9]{10,})""", "AWS key"),
    ]

    @classmethod
    def analyze(cls, doc: HTMLDocument) -> list[ScriptInfo]:
        """Analyze all scripts in the document."""
        results = []
        for script_node in doc.scripts:
            info = ScriptInfo(
                src=script_node.get_attr("src"),
                is_inline=not bool(script_node.get_attr("src")),
                content=script_node.inner_text if not script_node.get_attr("src") else "",
                nonce=script_node.get_attr("nonce"),
                integrity=script_node.get_attr("integrity"),
                crossorigin=script_node.get_attr("crossorigin"),
            )

            if info.is_inline and info.content:
                info.sinks = cls._find_patterns(info.content, cls.SINKS)
                info.sources = cls._find_patterns(info.content, cls.SOURCES)
                info.interesting_strings = cls._find_patterns(
                    info.content, cls.INTERESTING
                )

            results.append(info)
        return results

    @staticmethod
    def _find_patterns(code: str, patterns: list[tuple[str, str]]) -> list[str]:
        found = []
        for pattern, label in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                found.append(label)
        return found


# ═══════════════════════════════════════════════════════════════════════
# ReflectionMapper — Context-aware reflection detection
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ReflectionContext:
    """Where exactly a canary was reflected in the DOM."""
    canary: str
    context_type: ContextType
    tag: str = ""                # Parent tag name
    attribute: str = ""          # Attribute name if in an attribute
    line: int = 0
    offset: int = 0
    surrounding: str = ""        # ~50 chars around the reflection
    encoding: str = "raw"        # raw, html_entity, url_encoded, js_escaped
    is_filtered: bool = False    # Canary was modified/filtered


class ReflectionMapper:
    """
    Map exactly WHERE a canary string appears in parsed HTML.

    Unlike regex-based detection, this parser-based approach correctly
    identifies the DOM context — crucial for selecting the right XSS payload.
    """

    # Common encodings of the same canary
    @staticmethod
    def _canary_variants(canary: str) -> list[tuple[str, str]]:
        """Generate encoded variants of the canary to search for."""
        variants = [(canary, "raw")]
        # HTML entity encoded
        html_ent = canary.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
        if html_ent != canary:
            variants.append((html_ent, "html_entity"))
        # URL encoded
        url_enc = ""
        for c in canary:
            if c.isalnum():
                url_enc += c
            else:
                url_enc += f"%{ord(c):02X}"
        if url_enc != canary:
            variants.append((url_enc, "url_encoded"))
        # JS escape
        js_esc = canary.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
        if js_esc != canary:
            variants.append((js_esc, "js_escaped"))
        # Unicode escape
        unicode_esc = "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in canary)
        if unicode_esc != canary:
            variants.append((unicode_esc, "unicode_escaped"))
        return variants

    @classmethod
    def find_reflections(cls, doc: HTMLDocument, canary: str) -> list[ReflectionContext]:
        """
        Find all locations where the canary is reflected in the document.

        Returns a list of ReflectionContext objects with exact context type.
        """
        reflections = []
        variants = cls._canary_variants(canary)

        # Search in HTML comments
        for comment in doc.comments:
            for variant, encoding in variants:
                if variant in comment:
                    reflections.append(ReflectionContext(
                        canary=canary,
                        context_type=ContextType.HTML_COMMENT,
                        encoding=encoding,
                        surrounding=cls._get_surrounding(comment, variant),
                    ))

        # Walk the DOM tree
        cls._walk_node(doc.root, canary, variants, reflections)

        return reflections

    @classmethod
    def _walk_node(cls, node: DOMNode, canary: str,
                   variants: list[tuple[str, str]],
                   reflections: list[ReflectionContext]):
        """Recursively walk DOM and find canary reflections."""
        if not node:
            return

        # Check text content
        if node.text:
            for variant, encoding in variants:
                if variant in node.text:
                    ctx_type = cls._determine_text_context(node)
                    reflections.append(ReflectionContext(
                        canary=canary,
                        context_type=ctx_type,
                        tag=node.parent.tag if node.parent else "",
                        encoding=encoding,
                        line=node.source_line,
                        surrounding=cls._get_surrounding(node.text, variant),
                    ))

        # Check attribute values
        for attr_name, attr_value in node.attrs.items():
            if not attr_value:
                continue
            for variant, encoding in variants:
                if variant in attr_value:
                    ctx_type = cls._determine_attr_context(node, attr_name, attr_value)
                    reflections.append(ReflectionContext(
                        canary=canary,
                        context_type=ctx_type,
                        tag=node.tag,
                        attribute=attr_name,
                        encoding=encoding,
                        line=node.source_line,
                        surrounding=cls._get_surrounding(attr_value, variant),
                    ))

        # Recurse into children
        for child in node.children:
            cls._walk_node(child, canary, variants, reflections)

    @classmethod
    def _determine_text_context(cls, node: DOMNode) -> ContextType:
        """Determine the context type for a text reflection."""
        parent = node.parent
        if not parent:
            return ContextType.HTML_TEXT

        tag = parent.tag.lower()
        if tag == "script":
            return ContextType.SCRIPT_CODE
        if tag == "style":
            return ContextType.STYLE_PROPERTY
        if tag == "svg":
            return ContextType.SVG_CONTEXT
        if tag == "math":
            return ContextType.MATH_CONTEXT
        if tag == "!comment":
            return ContextType.HTML_COMMENT

        # Check for ancestor contexts
        if parent.has_ancestor("script"):
            return ContextType.SCRIPT_CODE
        if parent.has_ancestor("svg"):
            return ContextType.SVG_CONTEXT
        if parent.has_ancestor("style"):
            return ContextType.STYLE_PROPERTY

        return ContextType.HTML_TEXT

    @classmethod
    def _determine_attr_context(cls, node: DOMNode, attr_name: str,
                                 attr_value: str) -> ContextType:
        """Determine context type for an attribute reflection."""
        attr_lower = attr_name.lower()

        # Event handlers (onclick, onload, onerror, etc.)
        if attr_lower.startswith("on"):
            return ContextType.HTML_ATTRIBUTE_EVENT

        # URL attributes
        if attr_lower in ("href", "src", "action", "data", "formaction",
                          "poster", "background", "cite", "codebase",
                          "longdesc", "dynsrc", "lowsrc"):
            return ContextType.HTML_ATTRIBUTE_HREF

        # Style attribute
        if attr_lower == "style":
            return ContextType.HTML_ATTRIBUTE_STYLE

        # We can't perfectly determine quote style from parsed DOM,
        # but typically attributes use double quotes
        return ContextType.HTML_ATTRIBUTE_DOUBLE

    @staticmethod
    def _get_surrounding(text: str, needle: str, context_chars: int = 50) -> str:
        """Get surrounding context around a needle in text."""
        idx = text.find(needle)
        if idx == -1:
            return ""
        start = max(0, idx - context_chars)
        end = min(len(text), idx + len(needle) + context_chars)
        return text[start:end]


# ═══════════════════════════════════════════════════════════════════════
# MetaExtractor — Security-relevant meta information
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PageMeta:
    """Security-relevant metadata from the page."""
    charset: str = ""
    csp: str = ""                 # Content-Security-Policy from meta tag
    refresh_url: str = ""         # <meta http-equiv="refresh">
    generator: str = ""           # <meta name="generator">
    robots: str = ""
    viewport: str = ""
    description: str = ""
    keywords: str = ""
    author: str = ""
    frameworks: list[str] = field(default_factory=list)  # Detected JS frameworks
    technologies: list[str] = field(default_factory=list)


class MetaExtractor:
    """Extract security-relevant metadata from HTML."""

    FRAMEWORK_MARKERS = {
        "ng-app": "Angular",
        "data-reactroot": "React",
        "data-v-": "Vue.js",
        "__nuxt": "Nuxt.js",
        "__next": "Next.js",
        "data-svelte": "Svelte",
        "ember-view": "Ember.js",
        "data-turbo": "Hotwire/Turbo",
    }

    @classmethod
    def extract(cls, doc: HTMLDocument) -> PageMeta:
        """Extract page metadata."""
        meta = PageMeta()

        # Process <meta> tags
        for tag in doc.meta_tags:
            name = tag.get_attr("name", "").lower()
            http_equiv = tag.get_attr("http-equiv", "").lower()
            content = tag.get_attr("content", "")
            charset = tag.get_attr("charset", "")

            if charset:
                meta.charset = charset
            elif http_equiv == "content-type" and "charset=" in content.lower():
                meta.charset = content.split("charset=")[-1].strip()
            elif http_equiv == "content-security-policy":
                meta.csp = content
            elif http_equiv == "refresh" and "url=" in content.lower():
                meta.refresh_url = content.split("url=", 1)[-1].strip("' \"")
            elif name == "generator":
                meta.generator = content
            elif name == "robots":
                meta.robots = content
            elif name == "viewport":
                meta.viewport = content
            elif name == "description":
                meta.description = content
            elif name == "keywords":
                meta.keywords = content
            elif name == "author":
                meta.author = content

        # Detect JS frameworks from DOM attributes
        raw = doc.raw_html.lower()
        for marker, framework in cls.FRAMEWORK_MARKERS.items():
            if marker.lower() in raw:
                meta.frameworks.append(framework)

        # Detect technologies from script sources
        tech_patterns = {
            "jquery": "jQuery",
            "bootstrap": "Bootstrap",
            "angular": "Angular",
            "react": "React",
            "vue": "Vue.js",
            "lodash": "Lodash",
            "moment": "Moment.js",
            "axios": "Axios",
            "socket.io": "Socket.IO",
            "graphql": "GraphQL",
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
        }
        for script in doc.scripts:
            src = script.get_attr("src", "").lower()
            for pattern, tech_name in tech_patterns.items():
                if pattern in src and tech_name not in meta.technologies:
                    meta.technologies.append(tech_name)

        return meta


# ═══════════════════════════════════════════════════════════════════════
# CommentExtractor — Security analysis of HTML comments
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class CommentFinding:
    """A potentially security-relevant comment."""
    content: str
    category: str = ""     # "todo", "debug", "credential", "path", "version"
    severity: str = "INFO"


class CommentExtractor:
    """Extract and categorize HTML comments for security analysis."""

    PATTERNS = [
        (r"(?:password|passwd|pwd)\s*[:=]", "credential", "MEDIUM"),
        (r"(?:api[_-]?key|secret|token)\s*[:=]", "credential", "HIGH"),
        (r"(?:TODO|FIXME|HACK|BUG|XXX)", "todo", "LOW"),
        (r"(?:DEBUG|debug\s*[:=]\s*true|verbose)", "debug", "LOW"),
        (r"(?:/(?:var|etc|tmp|home|opt|usr)/\w+)", "path", "LOW"),
        (r"(?:v\d+\.\d+|version\s*[:=]\s*\d)", "version", "INFO"),
        (r"(?:internal|staging|dev\.|test\.)", "environment", "LOW"),
        (r"(?:database|mysql|postgres|mongodb|redis)://", "connection_string", "HIGH"),
        (r"(?:admin|root|superuser)", "privilege", "LOW"),
        (r"(?:disable|bypass|skip|workaround)", "security_bypass", "MEDIUM"),
        (r"<!--\s*\[if\s+IE", "ie_conditional", "INFO"),
    ]

    @classmethod
    def analyze(cls, doc: HTMLDocument) -> list[CommentFinding]:
        """Analyze HTML comments for security-relevant content."""
        findings = []
        for comment in doc.comments:
            comment_stripped = comment.strip()
            if not comment_stripped or len(comment_stripped) < 3:
                continue

            matched = False
            for pattern, category, severity in cls.PATTERNS:
                if re.search(pattern, comment_stripped, re.IGNORECASE):
                    findings.append(CommentFinding(
                        content=comment_stripped[:200],
                        category=category,
                        severity=severity,
                    ))
                    matched = True
                    break

            # Long comments that didn't match patterns are still notable
            if not matched and len(comment_stripped) > 50:
                findings.append(CommentFinding(
                    content=comment_stripped[:200],
                    category="verbose",
                    severity="INFO",
                ))

        return findings
