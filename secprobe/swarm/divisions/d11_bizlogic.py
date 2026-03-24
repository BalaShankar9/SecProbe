"""
Division 11 — Business Logic Vulnerability Agents (30 agents).

Targets flaws in application business logic: race conditions, payment tampering,
workflow bypass, rate limiting, notification abuse, feature misuse, referral/trial
fraud, financial attacks, idempotency/webhook issues, and API abuse.
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


def agents() -> list[AgentSpec]:
    """Return all 30 Division 11 agents."""
    return [
        # ── Race Conditions (3) ──────────────────────────────────────
        _s(
            "bizlogic-race-toctou", "TOCTOU Race Condition Specialist", 11,
            {Cap.HTTP_PROBE, Cap.TIME_BASED, Cap.PAYLOAD_INJECTION},
            description="Detects time-of-check-to-time-of-use race conditions by sending "
                        "parallel requests that exploit windows between authorization checks "
                        "and state-changing operations.",
            attack_types=("race-condition", "toctou"),
            cwe_ids=("CWE-367",),
            detection_patterns=(
                r"balance.*negative", r"quantity.*exceed", r"insufficient.*after",
            ),
            priority=Pri.HIGH,
            max_requests=200,
            tags=("race", "concurrency", "toctou"),
        ),
        _s(
            "bizlogic-race-double-spend", "Double-Spend Race Specialist", 11,
            {Cap.HTTP_PROBE, Cap.TIME_BASED, Cap.PAYLOAD_INJECTION},
            description="Exploits race conditions in balance-deducting operations by "
                        "firing concurrent withdrawal/purchase requests to achieve double "
                        "spending on single-balance accounts.",
            attack_types=("race-condition", "double-spend"),
            cwe_ids=("CWE-362", "CWE-367"),
            detection_patterns=(
                r"duplicate.*transaction", r"already.*processed",
            ),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("race", "double-spend", "financial"),
        ),
        _s(
            "bizlogic-race-limit-bypass", "Race-Based Limit Bypass Specialist", 11,
            {Cap.HTTP_PROBE, Cap.TIME_BASED},
            description="Bypasses quantity limits, coupon single-use constraints, and vote "
                        "counters by exploiting race windows in limit enforcement logic.",
            attack_types=("race-condition", "limit-bypass"),
            cwe_ids=("CWE-362",),
            detection_patterns=(
                r"limit.*exceeded", r"already.*redeemed",
            ),
            priority=Pri.NORMAL,
            max_requests=150,
            tags=("race", "limit", "coupon"),
        ),

        # ── Price/Payment Tampering (4) ──────────────────────────────
        _s(
            "bizlogic-price-tamper", "Client-Side Price Tampering Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Manipulates price, quantity, discount, and total fields in "
                        "client-submitted order data to test for server-side validation gaps.",
            attack_types=("price-tampering",),
            cwe_ids=("CWE-472",),
            detection_patterns=(
                r"order.*confirmed", r"payment.*accepted", r"success",
            ),
            priority=Pri.HIGH,
            max_requests=120,
            tags=("price", "tamper", "ecommerce"),
        ),
        _s(
            "bizlogic-currency-rounding", "Currency Rounding Abuse Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.STATISTICAL_ANALYSIS},
            description="Exploits floating-point rounding errors and currency conversion "
                        "edge cases to generate fractional-cent profits at scale.",
            attack_types=("currency-rounding", "financial-logic"),
            cwe_ids=("CWE-682",),
            detection_patterns=(
                r"amount.*0\.0[0-9]", r"rounding",
            ),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("currency", "rounding", "financial"),
        ),
        _s(
            "bizlogic-discount-stack", "Discount Stacking Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests for improper discount and coupon stacking by applying "
                        "multiple promotions, expired codes, and negative discounts in "
                        "sequence to achieve unauthorized price reductions.",
            attack_types=("discount-abuse",),
            cwe_ids=("CWE-840",),
            detection_patterns=(
                r"discount.*applied", r"coupon.*valid", r"total.*\$0",
            ),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("discount", "coupon", "stacking"),
        ),
        _s(
            "bizlogic-payment-gateway-bypass", "Payment Gateway Bypass Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Bypasses payment verification by manipulating callback URLs, "
                        "replaying success tokens, and forging gateway webhook signatures "
                        "to confirm orders without actual payment.",
            attack_types=("payment-bypass",),
            cwe_ids=("CWE-345",),
            detection_patterns=(
                r"payment.*verified", r"order.*complete", r"callback.*accepted",
            ),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("payment", "gateway", "bypass"),
        ),

        # ── Workflow Bypass (3) ──────────────────────────────────────
        _s(
            "bizlogic-step-skip", "Multi-Step Workflow Skip Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Bypasses multi-step workflows (checkout, registration, KYC) "
                        "by directly accessing later steps without completing prerequisites, "
                        "testing for missing server-side state validation.",
            attack_types=("workflow-bypass",),
            cwe_ids=("CWE-841",),
            detection_patterns=(
                r"step.*complete", r"verified", r"approved",
            ),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("workflow", "step-skip", "state"),
        ),
        _s(
            "bizlogic-approval-bypass", "Approval Chain Bypass Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests approval workflows for self-approval, approval chain "
                        "truncation, and role confusion by manipulating approver IDs "
                        "and approval status fields in request data.",
            attack_types=("approval-bypass",),
            cwe_ids=("CWE-863",),
            detection_patterns=(
                r"approved.*by", r"authorization.*granted",
            ),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("approval", "workflow", "authorization"),
        ),
        _s(
            "bizlogic-state-machine", "State Machine Violation Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Identifies invalid state transitions in order/ticket/account "
                        "lifecycles by forcing transitions that should be forbidden "
                        "(e.g., cancelled to shipped, closed to active).",
            attack_types=("state-violation",),
            cwe_ids=("CWE-841",),
            detection_patterns=(
                r"status.*changed", r"state.*updated", r"transition",
            ),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("state-machine", "lifecycle", "transition"),
        ),

        # ── Rate Limit / CAPTCHA (3) ─────────────────────────────────
        _s(
            "bizlogic-rate-limit-bypass", "Rate Limit Bypass Specialist", 11,
            {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION, Cap.HEADER_MANIPULATION},
            description="Bypasses rate limiting via header rotation (X-Forwarded-For, "
                        "X-Real-IP), endpoint variation, HTTP method switching, and "
                        "parameter pollution to exceed intended request thresholds.",
            attack_types=("rate-limit-bypass",),
            cwe_ids=("CWE-770",),
            detection_patterns=(
                r"rate.*limit", r"too.*many.*requests", r"429",
            ),
            priority=Pri.NORMAL,
            max_requests=200,
            tags=("rate-limit", "bypass", "throttle"),
        ),
        _s(
            "bizlogic-captcha-bypass", "CAPTCHA Bypass Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests CAPTCHA implementations for bypass via empty token submission, "
                        "token reuse, parameter removal, client-side-only validation, "
                        "and header-based bot detection evasion.",
            attack_types=("captcha-bypass",),
            cwe_ids=("CWE-804",),
            detection_patterns=(
                r"captcha.*invalid", r"verification.*failed",
            ),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("captcha", "bypass", "bot"),
        ),
        _s(
            "bizlogic-bruteforce-amplification", "Brute Force Amplification Specialist", 11,
            {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION},
            description="Discovers brute-force amplification vectors where a single "
                        "request can test multiple credentials, OTPs, or tokens "
                        "via array parameters, batch APIs, or GraphQL aliasing.",
            attack_types=("brute-force", "amplification"),
            cwe_ids=("CWE-307",),
            detection_patterns=(
                r"invalid.*credentials", r"account.*locked", r"attempts.*remaining",
            ),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("bruteforce", "amplification", "batch"),
        ),

        # ── Notification Abuse (3) ───────────────────────────────────
        _s(
            "bizlogic-email-bomb", "Email/SMS Notification Bombing Specialist", 11,
            {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION},
            description="Tests for notification flooding by triggering password resets, "
                        "verification emails, and alert SMS at high volume against "
                        "arbitrary recipient addresses.",
            attack_types=("notification-abuse", "email-bomb"),
            cwe_ids=("CWE-799",),
            detection_patterns=(
                r"email.*sent", r"notification.*delivered", r"sms.*queued",
            ),
            priority=Pri.LOW,
            max_requests=50,
            tags=("email", "sms", "notification", "flood"),
        ),
        _s(
            "bizlogic-notification-injection", "Notification Content Injection Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Injects malicious content into notification templates by "
                        "manipulating user-controlled fields (names, addresses, messages) "
                        "that appear in emails, SMS, or push notifications sent to victims.",
            attack_types=("notification-injection",),
            cwe_ids=("CWE-74",),
            detection_patterns=(
                r"email.*sent", r"message.*delivered",
            ),
            priority=Pri.NORMAL,
            max_requests=60,
            tags=("notification", "injection", "phishing"),
        ),
        _s(
            "bizlogic-notification-channel-swap", "Notification Channel Swap Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests whether notification delivery channels (email, phone, "
                        "webhook URL) can be swapped to attacker-controlled endpoints "
                        "to intercept OTPs, reset links, or sensitive alerts.",
            attack_types=("notification-redirect",),
            cwe_ids=("CWE-923",),
            detection_patterns=(
                r"channel.*updated", r"notification.*preference",
            ),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("notification", "channel", "redirect"),
        ),

        # ── Feature Abuse (3) ────────────────────────────────────────
        _s(
            "bizlogic-export-abuse", "Data Export Abuse Specialist", 11,
            {Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Abuses export functionality (CSV, PDF, report generation) to "
                        "extract bulk data beyond intended access, cause resource exhaustion "
                        "via oversized exports, or inject formulas into generated files.",
            attack_types=("export-abuse",),
            cwe_ids=("CWE-200",),
            detection_patterns=(
                r"export.*ready", r"download.*link", r"report.*generated",
            ),
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("export", "data", "abuse"),
        ),
        _s(
            "bizlogic-search-abuse", "Search/Filter Abuse Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Exploits overly permissive search and filter functionality to "
                        "enumerate hidden records, extract data via filter inference, "
                        "and cause denial-of-service through expensive query patterns.",
            attack_types=("search-abuse",),
            cwe_ids=("CWE-200", "CWE-400"),
            detection_patterns=(
                r"results.*found", r"total.*records",
            ),
            priority=Pri.LOW,
            max_requests=80,
            tags=("search", "filter", "enumeration"),
        ),
        _s(
            "bizlogic-invite-abuse", "Invitation System Abuse Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests invitation and sharing systems for privilege escalation "
                        "via role manipulation in invite parameters, self-invitation to "
                        "restricted resources, and invitation token reuse.",
            attack_types=("invite-abuse",),
            cwe_ids=("CWE-863",),
            detection_patterns=(
                r"invitation.*sent", r"member.*added", r"role.*assigned",
            ),
            priority=Pri.NORMAL,
            max_requests=60,
            tags=("invite", "sharing", "privilege"),
        ),

        # ── Referral / Trial Abuse (2) ───────────────────────────────
        _s(
            "bizlogic-referral-fraud", "Referral Program Fraud Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Detects self-referral loops, referral code brute-forcing, and "
                        "reward manipulation in referral programs by testing for missing "
                        "duplicate-account and self-referral protections.",
            attack_types=("referral-fraud",),
            cwe_ids=("CWE-837",),
            detection_patterns=(
                r"referral.*applied", r"bonus.*credited", r"reward",
            ),
            priority=Pri.LOW,
            max_requests=60,
            tags=("referral", "fraud", "reward"),
        ),
        _s(
            "bizlogic-trial-abuse", "Trial/Freemium Abuse Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests free trial systems for unlimited extension via account "
                        "recreation, trial period manipulation through timestamp tampering, "
                        "and premium feature access beyond trial scope.",
            attack_types=("trial-abuse",),
            cwe_ids=("CWE-840",),
            detection_patterns=(
                r"trial.*activated", r"subscription.*started", r"premium.*enabled",
            ),
            priority=Pri.LOW,
            max_requests=50,
            tags=("trial", "freemium", "abuse"),
        ),

        # ── Financial Attacks (3) ────────────────────────────────────
        _s(
            "bizlogic-refund-fraud", "Refund/Chargeback Fraud Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests refund workflows for double-refund exploits, refund "
                        "amount manipulation, refund-to-different-payment-method attacks, "
                        "and refund processing on already-consumed digital goods.",
            attack_types=("refund-fraud",),
            cwe_ids=("CWE-840",),
            detection_patterns=(
                r"refund.*processed", r"credit.*issued", r"amount.*refunded",
            ),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("refund", "fraud", "financial"),
        ),
        _s(
            "bizlogic-balance-manipulation", "Account Balance Manipulation Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Attacks internal wallet and credit systems by testing negative "
                        "transfer amounts, integer overflow in balance fields, "
                        "and transfer-to-self loops that generate phantom funds.",
            attack_types=("balance-manipulation",),
            cwe_ids=("CWE-682", "CWE-190"),
            detection_patterns=(
                r"balance.*updated", r"transfer.*complete", r"credit.*added",
            ),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("balance", "wallet", "manipulation"),
        ),
        _s(
            "bizlogic-tax-shipping-tamper", "Tax/Shipping Fee Tampering Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Manipulates tax calculations, shipping fees, and surcharges "
                        "by altering location data, weight fields, and shipping method "
                        "identifiers to reduce or eliminate order costs.",
            attack_types=("fee-tampering",),
            cwe_ids=("CWE-472",),
            detection_patterns=(
                r"shipping.*\$0", r"tax.*exempt", r"fee.*waived",
            ),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("tax", "shipping", "fee", "tamper"),
        ),

        # ── Idempotency / Webhook (3) ────────────────────────────────
        _s(
            "bizlogic-idempotency-violation", "Idempotency Key Violation Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests idempotency enforcement by replaying requests with "
                        "identical, missing, and manipulated idempotency keys to detect "
                        "duplicate processing, double charges, and state corruption.",
            attack_types=("idempotency-violation",),
            cwe_ids=("CWE-841",),
            detection_patterns=(
                r"duplicate", r"already.*processed", r"idempotency",
            ),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("idempotency", "replay", "duplicate"),
        ),
        _s(
            "bizlogic-webhook-abuse", "Webhook Security Specialist", 11,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Attacks webhook endpoints by forging signatures, replaying "
                        "old webhook payloads, injecting SSRF-triggering URLs in "
                        "webhook registration, and testing for missing authentication.",
            attack_types=("webhook-abuse",),
            cwe_ids=("CWE-345", "CWE-918"),
            detection_patterns=(
                r"webhook.*received", r"callback.*processed", r"event.*handled",
            ),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("webhook", "signature", "forgery"),
        ),
        _s(
            "bizlogic-replay-attack", "Transaction Replay Attack Specialist", 11,
            {Cap.HTTP_PROBE, Cap.TIME_BASED},
            description="Replays captured transaction requests to detect missing "
                        "nonce validation, timestamp verification, and replay "
                        "protection in financial and state-changing operations.",
            attack_types=("replay-attack",),
            cwe_ids=("CWE-294",),
            detection_patterns=(
                r"transaction.*complete", r"already.*used", r"expired.*token",
            ),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("replay", "nonce", "transaction"),
        ),

        # ── API Abuse (2) ────────────────────────────────────────────
        _s(
            "bizlogic-graphql-abuse", "GraphQL Business Logic Abuse Specialist", 11,
            {Cap.HTTP_PROBE, Cap.GRAPHQL_INTERACTION, Cap.PAYLOAD_INJECTION},
            description="Exploits GraphQL-specific business logic flaws including "
                        "query batching for brute force, nested query depth attacks, "
                        "alias-based rate limit bypass, and mutation field mass assignment.",
            attack_types=("graphql-abuse",),
            cwe_ids=("CWE-400", "CWE-915"),
            detection_patterns=(
                r"errors.*null", r"data.*\{",
            ),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("graphql", "batch", "depth", "abuse"),
        ),
        _s(
            "bizlogic-api-mass-assignment", "API Mass Assignment Specialist", 11,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.PAYLOAD_INJECTION},
            description="Tests REST and GraphQL APIs for mass assignment by injecting "
                        "extra fields (role, isAdmin, verified, balance) into creation "
                        "and update requests to escalate privileges or alter state.",
            attack_types=("mass-assignment",),
            cwe_ids=("CWE-915",),
            detection_patterns=(
                r"role.*admin", r"is_admin.*true", r"verified.*true",
            ),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("mass-assignment", "api", "privilege"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "bizlogic-commander", "Division 11 Business Logic Commander", 11,
            {Cap.COORDINATION, Cap.CONSENSUS_VOTING, Cap.KNOWLEDGE_SHARING},
            description="Coordinates all Division 11 agents, prioritizes business logic "
                        "tests based on detected application type (ecommerce, SaaS, fintech), "
                        "manages cross-agent deduplication, and synthesizes findings into "
                        "business-impact assessments.",
            attack_types=("business-logic",),
            cwe_ids=(),
            priority=Pri.CRITICAL,
            max_requests=50,
            tags=("commander", "coordinator", "bizlogic"),
        ),
    ]
