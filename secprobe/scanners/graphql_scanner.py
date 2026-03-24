"""
GraphQL Scanner — Introspection, injection, DoS, and authorization testing.

Capabilities:
  - Schema introspection & analysis
  - Query depth attacks (nested query DoS)
  - Batch query attacks
  - Injection testing through GraphQL parameters
  - Authorization bypass (accessing fields without proper auth)
  - Field suggestion abuse
  - Alias-based DoS
  - Directive overloading
"""

from __future__ import annotations

import json
import re
from typing import Optional
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


class GraphQLScanner(SmartScanner):
    """GraphQL API security scanner."""

    name = "GraphQL Scanner"
    description = "GraphQL introspection, injection, and DoS testing"

    GRAPHQL_PATHS = [
        "/graphql", "/graphiql", "/gql",
        "/api/graphql", "/api/gql",
        "/v1/graphql", "/v2/graphql",
        "/query", "/api/query",
        "/graphql/console", "/playground",
    ]

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name kind } }
            args { name type { name kind } }
          }
        }
      }
    }
    """

    def scan(self):
        """Execute GraphQL security scan."""
        target = normalize_url(self.config.target)

        # Step 1: Discover GraphQL endpoint
        endpoint = self._discover_endpoint(target)
        if not endpoint:
            print_status("No GraphQL endpoint found", "info")
            return

        print_status(f"GraphQL endpoint: {endpoint}", "success")

        # Step 2: Test introspection
        schema = self._test_introspection(endpoint)

        # Step 3: Security tests
        self._test_depth_limit(endpoint)
        self._test_batch_queries(endpoint)
        self._test_injection(endpoint, schema)
        self._test_field_suggestions(endpoint)
        self._test_alias_dos(endpoint)
        self._test_directive_overloading(endpoint)
        self._test_debug_mode(endpoint)
        self._test_ide_endpoints(target)

    def _discover_endpoint(self, target: str) -> Optional[str]:
        """Discover the GraphQL endpoint."""
        for path in self.GRAPHQL_PATHS:
            url = urljoin(target + "/", path.lstrip("/"))
            try:
                # Try POST with introspection
                resp = self.http_client.post(
                    url,
                    json={"query": "{__typename}"},
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.timeout,
                )
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            return url
                    except Exception:
                        pass
                # Try GET
                resp = self.http_client.get(
                    f"{url}?query={{__typename}}",
                    timeout=self.config.timeout,
                )
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            return url
                    except Exception:
                        pass
            except Exception:
                continue
        return None

    def _graphql_query(self, endpoint: str, query: str,
                       variables: Optional[dict] = None) -> Optional[dict]:
        """Execute a GraphQL query and return parsed response."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            resp = self.http_client.post(
                endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.config.timeout,
            )
            if resp and resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def _test_introspection(self, endpoint: str) -> Optional[dict]:
        """Test if introspection is enabled (it shouldn't be in production)."""
        result = self._graphql_query(endpoint, self.INTROSPECTION_QUERY)

        if result and "data" in result and result["data"].get("__schema"):
            schema = result["data"]["__schema"]
            types = schema.get("types", [])
            user_types = [t for t in types if not t["name"].startswith("__")]
            mutation_type = schema.get("mutationType")

            self.add_finding(
                title="GraphQL Introspection Enabled",
                severity=Severity.MEDIUM,
                description=f"Full schema introspection is enabled, exposing {len(user_types)} types "
                           f"and {'mutations' if mutation_type else 'queries only'}. "
                           f"Attackers can map the entire API surface.",
                recommendation="Disable introspection in production environments. "
                              "Use allowlists for permitted queries.",
                evidence=f"Types discovered: {len(user_types)}\n"
                        f"Has mutations: {bool(mutation_type)}\n"
                        f"Sample types: {', '.join(t['name'] for t in user_types[:10])}",
                category="GraphQL",
                url=endpoint,
                cwe="CWE-200",
            )

            # Analyze schema for sensitive types
            sensitive_patterns = [
                "user", "admin", "auth", "token", "password", "secret",
                "payment", "credit", "card", "session", "role", "permission",
            ]
            for t in user_types:
                name_lower = t["name"].lower()
                for pattern in sensitive_patterns:
                    if pattern in name_lower:
                        fields = t.get("fields") or []
                        field_names = [f["name"] for f in fields]
                        self.add_finding(
                            title=f"Sensitive GraphQL Type Exposed: {t['name']}",
                            severity=Severity.LOW,
                            description=f"The GraphQL type '{t['name']}' with fields "
                                       f"{', '.join(field_names[:10])} is exposed via introspection.",
                            recommendation="Review access controls for this type. Consider field-level authorization.",
                            evidence=f"Type: {t['name']}\nFields: {', '.join(field_names)}",
                            category="GraphQL",
                            url=endpoint,
                            cwe="CWE-200",
                        )
                        break

            return schema
        return None

    def _test_depth_limit(self, endpoint: str):
        """Test for query depth limit (nested query DoS)."""
        # Build progressively deeper queries
        depths = [5, 10, 20, 50]
        max_successful_depth = 0

        for depth in depths:
            # Build nested query
            query = "{ __typename "
            for i in range(depth):
                query += "... on Query { __typename "
            for i in range(depth):
                query += "} "
            query += "}"

            result = self._graphql_query(endpoint, query)
            if result and "data" in result:
                max_successful_depth = depth
            elif result and "errors" in result:
                # Check if it's a depth limit error
                error_msg = str(result.get("errors", []))
                if "depth" in error_msg.lower() or "complexity" in error_msg.lower():
                    break

        if max_successful_depth >= 20:
            self.add_finding(
                title="No GraphQL Query Depth Limit",
                severity=Severity.MEDIUM,
                description=f"Queries with depth {max_successful_depth}+ are accepted. "
                           f"This enables nested query DoS attacks that can exhaust server resources.",
                recommendation="Implement query depth limiting (recommended max: 10). "
                              "Use query complexity analysis. Set timeouts for query execution.",
                evidence=f"Maximum successful depth: {max_successful_depth}",
                category="GraphQL",
                url=endpoint,
                cwe="CWE-770",
            )

    def _test_batch_queries(self, endpoint: str):
        """Test for batch query support (amplification attacks)."""
        # Send array of queries
        batch = [
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
        ]

        try:
            resp = self.http_client.post(
                endpoint,
                json=batch,
                headers={"Content-Type": "application/json"},
                timeout=self.config.timeout,
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) >= 5:
                        self.add_finding(
                            title="GraphQL Batch Query Support Enabled",
                            severity=Severity.LOW,
                            description="The GraphQL endpoint accepts batched queries. "
                                       "Attackers can amplify attacks by sending many queries in a single request, "
                                       "bypassing rate limiting.",
                            recommendation="Limit batch query size to a maximum of 5-10 queries. "
                                          "Implement per-query rate limiting, not just per-request.",
                            evidence=f"Sent 5 batched queries, received {len(data)} responses",
                            category="GraphQL",
                            url=endpoint,
                            cwe="CWE-770",
                        )
                except Exception:
                    pass
        except Exception:
            pass

    def _test_injection(self, endpoint: str, schema: Optional[dict]):
        """Test for injection through GraphQL arguments."""
        injection_payloads = {
            "sqli": ["' OR '1'='1'--", '" OR "1"="1"--', "1; DROP TABLE users;"],
            "nosql": ['{"$gt":""}', '{"$ne":null}'],
            "xss": ['<img src=x onerror=alert(1)>', '<script>alert(1)</script>'],
        }

        # Try injection in a simple query with arguments
        for attack_type, payloads in injection_payloads.items():
            for payload in payloads:
                # Test via query argument
                query = f'{{ search(query: "{self._escape_graphql(payload)}") {{ id }} }}'
                result = self._graphql_query(endpoint, query)

                if result and result.get("errors"):
                    error_text = str(result["errors"]).lower()
                    if any(indicator in error_text for indicator in
                           ["sql", "syntax", "mongo", "database", "query"]):
                        self.add_finding(
                            title=f"Potential {attack_type.upper()} via GraphQL Arguments",
                            severity=Severity.HIGH,
                            description=f"Database error messages leak through GraphQL when injecting "
                                       f"into query arguments, suggesting {attack_type} vulnerability.",
                            recommendation="Use parameterized database queries. Sanitize all GraphQL argument values. "
                                          "Do not expose raw database errors.",
                            evidence=f"Payload: {payload}\nError: {error_text[:200]}",
                            category="GraphQL",
                            url=endpoint,
                            cwe="CWE-89" if attack_type == "sqli" else "CWE-943",
                        )
                        break

    def _test_field_suggestions(self, endpoint: str):
        """Test for field suggestion information disclosure."""
        # Query with a misspelled field to see if suggestions are returned
        result = self._graphql_query(endpoint, "{ usr { id } }")

        if result and result.get("errors"):
            error_text = str(result["errors"])
            if "did you mean" in error_text.lower() or "suggestion" in error_text.lower():
                self.add_finding(
                    title="GraphQL Field Suggestion Enabled",
                    severity=Severity.LOW,
                    description="The GraphQL server suggests valid field names when invalid ones are queried. "
                               "Attackers can enumerate the schema without introspection.",
                    recommendation="Disable field suggestions in production. Use generic error messages.",
                    evidence=f"Query: {{ usr {{ id }} }}\nResponse: {error_text[:300]}",
                    category="GraphQL",
                    url=endpoint,
                    cwe="CWE-200",
                )

    def _test_alias_dos(self, endpoint: str):
        """Test for alias-based query amplification."""
        # Build query with many aliases
        aliases = []
        for i in range(100):
            aliases.append(f"a{i}: __typename")
        query = "{ " + " ".join(aliases) + " }"

        result = self._graphql_query(endpoint, query)
        if result and "data" in result and len(result["data"]) >= 100:
            self.add_finding(
                title="GraphQL Alias-based Amplification Possible",
                severity=Severity.MEDIUM,
                description="The server allows 100+ aliases in a single query without limits. "
                           "Attackers can amplify expensive operations using aliases.",
                recommendation="Limit the number of aliases per query. Implement query cost analysis.",
                evidence=f"100 aliases accepted, received {len(result['data'])} fields in response",
                category="GraphQL",
                url=endpoint,
                cwe="CWE-770",
            )

    def _test_directive_overloading(self, endpoint: str):
        """Test for directive overloading DoS."""
        # Build query with many repeated directives
        directives = " @include(if: true)" * 50
        query = f"{{ __typename {directives} }}"

        result = self._graphql_query(endpoint, query)
        if result and "data" in result:
            self.add_finding(
                title="GraphQL Directive Overloading Accepted",
                severity=Severity.LOW,
                description="The server accepts queries with 50+ repeated directives, "
                           "which could be used for DoS or WAF bypass.",
                recommendation="Limit the number of directives per field. Validate directive usage.",
                evidence="50 @include directives accepted without error",
                category="GraphQL",
                url=endpoint,
                cwe="CWE-770",
            )

    def _test_debug_mode(self, endpoint: str):
        """Test for debug/developer mode indicators."""
        # Send malformed query
        result = self._graphql_query(endpoint, "{ invalid query syntax !@#$ }")

        if result and result.get("errors"):
            error_text = json.dumps(result["errors"], indent=2)
            debug_indicators = [
                "stack", "trace", "line", "column", "file",
                "node_modules", "graphql-js", "apollo", "express",
                "/src/", "/app/", "internal",
            ]
            for indicator in debug_indicators:
                if indicator in error_text.lower():
                    self.add_finding(
                        title="GraphQL Debug Information Exposed",
                        severity=Severity.MEDIUM,
                        description="GraphQL error responses contain debug information (stack traces, "
                                   "file paths, or internal details) that could help attackers.",
                        recommendation="Disable debug mode in production. Use generic error messages. "
                                      "Remove stack traces and internal paths from error responses.",
                        evidence=f"Debug indicator: '{indicator}'\nError sample: {error_text[:300]}",
                        category="GraphQL",
                        url=endpoint,
                        cwe="CWE-209",
                    )
                    break

    def _test_ide_endpoints(self, target: str):
        """Test for exposed GraphQL IDE endpoints."""
        ide_paths = [
            "/graphiql", "/playground", "/altair",
            "/graphql-playground", "/voyager",
            "/graphql/console", "/graphql-explorer",
        ]

        for path in ide_paths:
            url = urljoin(target + "/", path.lstrip("/"))
            try:
                resp = self.http_client.get(url, timeout=self.config.timeout)
                if resp and resp.status_code == 200:
                    if any(indicator in resp.text.lower() for indicator in
                           ["graphiql", "playground", "altair", "voyager", "graphql"]):
                        self.add_finding(
                            title=f"GraphQL IDE Exposed: {path}",
                            severity=Severity.LOW,
                            description=f"A GraphQL development IDE is accessible at {url}. "
                                       f"This provides attackers with a convenient interface to explore and attack the API.",
                            recommendation="Disable GraphQL IDEs in production environments.",
                            evidence=f"URL: {url}\nStatus: {resp.status_code}",
                            category="GraphQL",
                            url=url,
                            cwe="CWE-16",
                        )
            except Exception:
                continue

    def _escape_graphql(self, text: str) -> str:
        """Escape text for embedding in GraphQL string literals."""
        return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
