"""
Division 9: Cloud & Serverless — 35 agents.

Covers S3/GCS/Azure storage, cloud metadata SSRF, IAM/privilege escalation,
Firebase/Cognito, Kubernetes, serverless, CDN/WAF bypass, Docker/registry,
secrets/KMS, network/logging, and supply chain/cost vectors.
"""
from __future__ import annotations

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


def agents() -> list[AgentSpec]:
    return [
        # ── S3 / GCS / Azure Storage (4) ────────────────────────────
        _s(
            "cl-s3-bucket", "AWS S3 Bucket Misconfiguration Scanner", 9,
            {Cap.HTTP_PROBE, Cap.DATA_EXTRACTION, Cap.OSINT},
            description="Tests AWS S3 buckets for public listing (ListBucket), unauthenticated "
                        "read/write (GetObject, PutObject), and ACL misconfigurations",
            attack_types=("cloud-storage-exposure",),
            cwe_ids=("CWE-284", "CWE-732"),
            target_technologies=("aws", "s3"),
            detection_patterns=(
                r"<ListBucketResult",
                r"NoSuchBucket",
                r"AccessDenied",
                r"AllUsers",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("aws", "s3", "bucket", "public-access"),
        ),
        _s(
            "cl-gcs-bucket", "GCS Bucket Misconfiguration Scanner", 9,
            {Cap.HTTP_PROBE, Cap.DATA_EXTRACTION, Cap.OSINT},
            description="Tests Google Cloud Storage buckets for public access, uniform "
                        "bucket-level access misconfigurations, and signed URL leakage",
            attack_types=("cloud-storage-exposure",),
            cwe_ids=("CWE-284", "CWE-732"),
            target_technologies=("gcp", "gcs"),
            detection_patterns=(
                r"storage\.googleapis\.com",
                r"<ListBucketResult",
                r"NoSuchKey",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("gcp", "gcs", "bucket", "public-access"),
        ),
        _s(
            "cl-azure-blob", "Azure Blob Storage Scanner", 9,
            {Cap.HTTP_PROBE, Cap.DATA_EXTRACTION, Cap.OSINT},
            description="Tests Azure Blob Storage for public container listing, "
                        "SAS token misconfigurations, and anonymous blob access",
            attack_types=("cloud-storage-exposure",),
            cwe_ids=("CWE-284", "CWE-732"),
            target_technologies=("azure", "blob"),
            detection_patterns=(
                r"\.blob\.core\.windows\.net",
                r"<EnumerationResults",
                r"BlobNotFound",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("azure", "blob", "storage", "public-access"),
        ),
        _s(
            "cl-storage-enum", "Cloud Storage Bucket Enumerator", 9,
            {Cap.HTTP_PROBE, Cap.OSINT, Cap.DNS_ENUM},
            description="Enumerates cloud storage bucket names via permutation of target "
                        "domain, company name, and common naming patterns across providers",
            attack_types=("cloud-storage-exposure",),
            cwe_ids=("CWE-200",),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            max_requests=300,
            tags=("cloud", "enumeration", "bucket-names"),
        ),

        # ── Cloud Metadata SSRF (3) ─────────────────────────────────
        _s(
            "cl-imds-v1", "AWS IMDSv1 Metadata SSRF Tester", 9,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Tests for SSRF to AWS Instance Metadata Service v1 at "
                        "169.254.169.254 to extract IAM role credentials and instance identity",
            attack_types=("ssrf", "cloud-metadata"),
            cwe_ids=("CWE-918",),
            target_technologies=("aws",),
            payloads=("ssrf_aws_imds.txt",),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("aws", "imds", "ssrf", "credentials"),
        ),
        _s(
            "cl-gcp-metadata", "GCP Metadata SSRF Tester", 9,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Tests for SSRF to GCP metadata server (metadata.google.internal) "
                        "to extract service account tokens and project configuration",
            attack_types=("ssrf", "cloud-metadata"),
            cwe_ids=("CWE-918",),
            target_technologies=("gcp",),
            payloads=("ssrf_gcp_metadata.txt",),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("gcp", "metadata", "ssrf", "credentials"),
        ),
        _s(
            "cl-azure-metadata", "Azure IMDS Metadata SSRF Tester", 9,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Tests for SSRF to Azure Instance Metadata Service at "
                        "169.254.169.254 to extract managed identity tokens and subscription info",
            attack_types=("ssrf", "cloud-metadata"),
            cwe_ids=("CWE-918",),
            target_technologies=("azure",),
            payloads=("ssrf_azure_imds.txt",),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("azure", "imds", "ssrf", "credentials"),
        ),

        # ── IAM / Escalation (3) ────────────────────────────────────
        _s(
            "cl-iam-enum", "Cloud IAM Policy Enumerator", 9,
            {Cap.API_INTERACTION, Cap.DATA_EXTRACTION, Cap.PRIVILEGE_ESCALATION},
            description="Enumerates IAM policies, roles, and permissions to identify "
                        "overprivileged service accounts and exploitable permission boundaries",
            attack_types=("iam-misconfiguration",),
            cwe_ids=("CWE-250", "CWE-269"),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("iam", "permissions", "enumeration"),
        ),
        _s(
            "cl-iam-escalation", "IAM Privilege Escalation Specialist", 9,
            {Cap.API_INTERACTION, Cap.PRIVILEGE_ESCALATION, Cap.CHAIN_BUILDING},
            description="Discovers IAM privilege escalation paths: iam:PassRole, "
                        "sts:AssumeRole chains, Lambda function abuse, and policy attachment",
            attack_types=("privilege-escalation",),
            cwe_ids=("CWE-269",),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.HIGH,
            min_mode=Mode.REDTEAM,
            tags=("iam", "privilege-escalation", "assume-role"),
        ),
        _s(
            "cl-sts-confusion", "Cross-Account Confusion Tester", 9,
            {Cap.API_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.PRIVILEGE_ESCALATION},
            description="Tests for confused deputy and cross-account access vulnerabilities "
                        "via STS role assumption without proper external ID validation",
            attack_types=("privilege-escalation",),
            cwe_ids=("CWE-441", "CWE-269"),
            target_technologies=("aws",),
            priority=Pri.NORMAL,
            min_mode=Mode.REDTEAM,
            tags=("sts", "confused-deputy", "cross-account"),
        ),

        # ── Firebase / Cognito (3) ──────────────────────────────────
        _s(
            "cl-firebase-rules", "Firebase Security Rules Auditor", 9,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Tests Firebase Realtime Database and Firestore rules for overly "
                        "permissive read/write access allowing unauthorized data manipulation",
            attack_types=("firebase-misconfiguration",),
            cwe_ids=("CWE-284", "CWE-732"),
            target_technologies=("firebase",),
            detection_patterns=(
                r"firebaseio\.com",
                r"firestore\.googleapis\.com",
                r'"rules":\s*\{',
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("firebase", "rules", "database"),
        ),
        _s(
            "cl-firebase-storage", "Firebase Storage ACL Tester", 9,
            {Cap.HTTP_PROBE, Cap.DATA_EXTRACTION, Cap.PATTERN_MATCHING},
            description="Tests Firebase Cloud Storage rules for public upload/download, "
                        "missing authentication checks, and user-specific file access bypass",
            attack_types=("firebase-misconfiguration",),
            cwe_ids=("CWE-284",),
            target_technologies=("firebase",),
            detection_patterns=(
                r"firebasestorage\.googleapis\.com",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("firebase", "storage", "acl"),
        ),
        _s(
            "cl-cognito-miscfg", "AWS Cognito Misconfiguration Scanner", 9,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
            description="Tests Cognito user pools for self-registration abuse, unverified "
                        "attribute modification, group escalation, and identity pool confusion",
            attack_types=("cognito-misconfiguration",),
            cwe_ids=("CWE-287", "CWE-284"),
            target_technologies=("aws", "cognito"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("cognito", "user-pool", "identity"),
        ),

        # ── Kubernetes (4) ──────────────────────────────────────────
        _s(
            "cl-k8s-etcd", "Kubernetes etcd Exposure Scanner", 9,
            {Cap.PORT_SCAN, Cap.API_INTERACTION, Cap.DATA_EXTRACTION},
            description="Detects exposed etcd instances (port 2379/2380) that store all "
                        "Kubernetes cluster state including secrets in plaintext",
            attack_types=("k8s-misconfiguration",),
            cwe_ids=("CWE-306", "CWE-311"),
            target_technologies=("kubernetes", "etcd"),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("kubernetes", "etcd", "secrets"),
        ),
        _s(
            "cl-k8s-kubelet", "Kubelet API Exploitation Agent", 9,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.PRIVILEGE_ESCALATION},
            description="Tests Kubelet API (port 10250/10255) for unauthenticated access "
                        "to /pods, /run, /exec endpoints enabling container command execution",
            attack_types=("k8s-misconfiguration",),
            cwe_ids=("CWE-306",),
            target_technologies=("kubernetes",),
            detection_patterns=(
                r"/pods",
                r"/run/",
                r"kubelet",
            ),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("kubernetes", "kubelet", "rce"),
        ),
        _s(
            "cl-k8s-service-account", "K8s Service Account Token Tester", 9,
            {Cap.API_INTERACTION, Cap.DATA_EXTRACTION, Cap.PRIVILEGE_ESCALATION},
            description="Tests mounted service account tokens in pods for excessive RBAC "
                        "permissions that allow secret listing, pod creation, or cluster-admin",
            attack_types=("k8s-misconfiguration",),
            cwe_ids=("CWE-250",),
            target_technologies=("kubernetes",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("kubernetes", "service-account", "rbac"),
        ),
        _s(
            "cl-k8s-network-policy", "K8s Network Policy Auditor", 9,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
            description="Audits Kubernetes network policies for missing ingress/egress "
                        "rules, overly permissive pod selectors, and namespace isolation gaps",
            attack_types=("k8s-misconfiguration",),
            cwe_ids=("CWE-284",),
            target_technologies=("kubernetes",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("kubernetes", "network-policy", "isolation"),
        ),

        # ── Serverless (3) ──────────────────────────────────────────
        _s(
            "cl-lambda-miscfg", "AWS Lambda Misconfiguration Scanner", 9,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
            description="Tests Lambda functions for overprivileged execution roles, "
                        "environment variable secrets, public function URLs, and layer abuse",
            attack_types=("serverless-misconfiguration",),
            cwe_ids=("CWE-250", "CWE-798"),
            target_technologies=("aws", "lambda"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("lambda", "serverless", "permissions"),
        ),
        _s(
            "cl-api-gateway", "API Gateway Misconfiguration Scanner", 9,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.HEADER_MANIPULATION},
            description="Tests API Gateway configurations for missing authentication, "
                        "stage variable injection, response header leakage, and throttle bypass",
            attack_types=("serverless-misconfiguration",),
            cwe_ids=("CWE-306", "CWE-284"),
            target_technologies=("aws", "api-gateway"),
            detection_patterns=(
                r"x-amzn-RequestId",
                r"x-amz-apigw-id",
                r"Forbidden",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("api-gateway", "serverless", "auth"),
        ),
        _s(
            "cl-event-injection", "Serverless Event Injection Tester", 9,
            {Cap.PAYLOAD_INJECTION, Cap.API_INTERACTION, Cap.HTTP_PROBE},
            description="Tests for injection in serverless event sources: S3 trigger "
                        "filenames, SQS/SNS message bodies, and DynamoDB stream payloads",
            attack_types=("serverless-injection",),
            cwe_ids=("CWE-94",),
            target_technologies=("aws", "lambda"),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("serverless", "event-injection", "lambda"),
        ),

        # ── CDN / WAF Bypass (3) ────────────────────────────────────
        _s(
            "cl-cdn-origin-find", "CDN Origin IP Discovery Agent", 9,
            {Cap.DNS_ENUM, Cap.HTTP_PROBE, Cap.OSINT},
            description="Discovers origin server IPs behind CDN/WAF by querying DNS history, "
                        "certificate transparency, and common misconfiguration patterns",
            attack_types=("waf-bypass",),
            cwe_ids=("CWE-693",),
            target_technologies=("cloudflare", "akamai", "cloudfront", "fastly"),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("cdn", "origin", "waf-bypass"),
        ),
        _s(
            "cl-waf-fingerprint", "WAF Fingerprinting Agent", 9,
            {Cap.HTTP_PROBE, Cap.TECH_FINGERPRINT, Cap.PATTERN_MATCHING},
            description="Fingerprints WAF vendor and ruleset version via response analysis, "
                        "error signatures, and blocking page fingerprints",
            attack_types=("waf-detection",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"cloudflare",
                r"akamai",
                r"mod_security",
                r"AWS WAF",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("waf", "fingerprint", "detection"),
        ),
        _s(
            "cl-cdn-cache-abuse", "CDN Cache Manipulation Tester", 9,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests CDN caching behavior for cache key manipulation, "
                        "cache deception via path confusion, and cache poisoning vectors",
            attack_types=("cache-poisoning",),
            cwe_ids=("CWE-524",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("cdn", "cache", "poisoning"),
        ),

        # ── Docker / Registry (3) ───────────────────────────────────
        _s(
            "cl-docker-registry", "Docker Registry Exposure Scanner", 9,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.DATA_EXTRACTION},
            description="Detects exposed Docker registries (v2 API) with unauthenticated "
                        "catalog listing, image pulling, and manifest inspection",
            attack_types=("registry-exposure",),
            cwe_ids=("CWE-306", "CWE-284"),
            target_technologies=("docker",),
            detection_patterns=(
                r"/v2/_catalog",
                r"Docker-Distribution-Api-Version",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("docker", "registry", "unauthenticated"),
        ),
        _s(
            "cl-container-escape", "Container Escape Vector Scanner", 9,
            {Cap.API_INTERACTION, Cap.PRIVILEGE_ESCALATION, Cap.PATTERN_MATCHING},
            description="Tests for container escape vectors: privileged mode, host PID/net "
                        "namespace, mounted Docker socket, CAP_SYS_ADMIN, and cgroup escape",
            attack_types=("container-escape",),
            cwe_ids=("CWE-250",),
            target_technologies=("docker", "containerd"),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("container", "escape", "privilege"),
        ),
        _s(
            "cl-image-vuln", "Container Image Vulnerability Scanner", 9,
            {Cap.PATTERN_MATCHING, Cap.API_INTERACTION, Cap.COMPLIANCE_MAPPING},
            description="Scans container image layers for known OS and library CVEs, "
                        "hardcoded secrets in environment variables, and root user execution",
            attack_types=("known-cve",),
            cwe_ids=("CWE-1035",),
            target_technologies=("docker",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("container", "image", "cve"),
        ),

        # ── Secret / KMS (3) ───────────────────────────────────────
        _s(
            "cl-env-secret", "Cloud Environment Secret Scanner", 9,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Scans for exposed cloud secrets in environment variables, "
                        "Lambda configurations, ECS task definitions, and instance user-data",
            attack_types=("secret-exposure",),
            cwe_ids=("CWE-798", "CWE-312"),
            detection_patterns=(
                r"AKIA[0-9A-Z]{16}",
                r"(?:aws_secret|AWS_SECRET)",
                r"(?:AZURE_CLIENT_SECRET|AZURE_TENANT)",
                r"(?:GOOGLE_APPLICATION_CREDENTIALS)",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("secrets", "environment", "credentials"),
        ),
        _s(
            "cl-kms-miscfg", "KMS Key Policy Auditor", 9,
            {Cap.API_INTERACTION, Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Audits KMS key policies for overly permissive grants, "
                        "cross-account access without conditions, and disabled key rotation",
            attack_types=("kms-misconfiguration",),
            cwe_ids=("CWE-320", "CWE-284"),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("kms", "encryption", "key-management"),
        ),
        _s(
            "cl-vault-exposure", "Secret Manager Exposure Scanner", 9,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.DATA_EXTRACTION},
            description="Detects exposed HashiCorp Vault, AWS Secrets Manager, and "
                        "GCP Secret Manager endpoints with weak or missing authentication",
            attack_types=("secret-exposure",),
            cwe_ids=("CWE-306", "CWE-798"),
            target_technologies=("vault", "aws", "gcp"),
            detection_patterns=(
                r"/v1/secret",
                r"/v1/sys/health",
                r"vault\.hashicorp",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("vault", "secrets-manager", "exposure"),
        ),

        # ── Network / Logging (3) ───────────────────────────────────
        _s(
            "cl-sg-audit", "Security Group / Firewall Rule Auditor", 9,
            {Cap.API_INTERACTION, Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Audits cloud security groups and firewall rules for overly "
                        "permissive inbound rules (0.0.0.0/0 on sensitive ports)",
            attack_types=("firewall-misconfiguration",),
            cwe_ids=("CWE-284",),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("security-group", "firewall", "network"),
        ),
        _s(
            "cl-logging-gaps", "Cloud Logging Gap Detector", 9,
            {Cap.API_INTERACTION, Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Detects disabled CloudTrail, VPC Flow Logs, or GCP audit logging "
                        "that would allow attacker activity to go unmonitored",
            attack_types=("logging-gap",),
            cwe_ids=("CWE-778",),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("logging", "monitoring", "compliance"),
        ),
        _s(
            "cl-vpc-exposure", "VPC / Network Peering Auditor", 9,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
            description="Audits VPC configurations for public subnet exposure, missing "
                        "NACLs, overly permissive peering connections, and route table issues",
            attack_types=("network-misconfiguration",),
            cwe_ids=("CWE-284",),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("vpc", "network", "peering"),
        ),

        # ── Supply Chain / Cost (2) ─────────────────────────────────
        _s(
            "cl-supply-chain-cloud", "Cloud Supply Chain Risk Analyzer", 9,
            {Cap.API_INTERACTION, Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Analyzes cloud resource dependencies for supply chain risks: "
                        "shared AMIs, public ECR images, and third-party Lambda layers",
            attack_types=("supply-chain",),
            cwe_ids=("CWE-1357",),
            target_technologies=("aws", "gcp"),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("supply-chain", "ami", "layers"),
        ),
        _s(
            "cl-cost-abuse", "Cloud Resource Abuse Detector", 9,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING, Cap.HTTP_PROBE},
            description="Detects cloud resource abuse vectors: cryptocurrency mining via "
                        "Lambda/Functions, DDoS amplification, and unlimited API quota exploitation",
            attack_types=("resource-abuse",),
            cwe_ids=("CWE-770",),
            target_technologies=("aws", "gcp", "azure"),
            priority=Pri.LOW,
            min_mode=Mode.AUDIT,
            tags=("cost", "abuse", "cryptomining"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "cl-commander", "Division 9 Commander — Cloud & Serverless", 9,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Orchestrates all Division 9 cloud agents. Detects target cloud "
                        "provider first, then activates provider-specific agents. Coordinates "
                        "metadata SSRF chains with IAM escalation and container escape paths",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            tags=("commander", "division-9", "cloud"),
            max_requests=0,
            timeout=600,
        ),
    ]
