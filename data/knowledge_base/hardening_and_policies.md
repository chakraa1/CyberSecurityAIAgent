# Cybersecurity Knowledge Base (RAG corpus)

Each section below is indexed as a separate document for retrieval.

## SSH brute-force defense
Repeated failed SSH password attempts from a single source IP indicate a
brute-force attack. Mitigate with fail2ban, disable password auth in favour of
public keys, restrict the SSH port via security groups, and rate-limit with
firewall rules. Map to NIST 800-53 AC-7 (unsuccessful logon attempts).

## SQL injection
SQL injection occurs when untrusted input is concatenated into SQL queries.
Indicators include `' OR '1'='1`, `UNION SELECT`, and tooling user-agents such
as sqlmap. Mitigate with parameterised queries / prepared statements, input
validation, least-privilege DB accounts, and a WAF. Maps to OWASP A03:2021.

## Cross-site scripting (XSS)
XSS injects scripts such as `<script>alert(1)</script>` into pages. Mitigate by
contextual output encoding, a strict Content-Security-Policy, and sanitising
user input. Maps to OWASP A03:2021.

## Path traversal and secret exposure
Requests like `../../../../etc/passwd` or `/admin/.env` attempt to read files
outside the web root or leak secrets. Mitigate by canonicalising paths, denying
dotfiles, and never serving `.env` files. Rotate any exposed credentials.

## Database hardening (MSSQL, MySQL, Oracle, PostgreSQL)
Do not expose database ports (1433/3306/1521/5432) to the public internet.
Enforce TLS, strong/rotated credentials, least-privilege roles, audit logging,
and disable default/sample accounts. Patch promptly (e.g. CVE-2012-2122 MySQL
auth bypass, CVE-2020-1472 affects Windows domains hosting MSSQL).

## Docker image security
Avoid running containers as root, pin base image digests, scan images for CVEs,
drop unnecessary Linux capabilities, set read-only root filesystems where
possible, and never bake secrets into image layers.

## NIST CSF mapping
- Identify: asset inventory, risk assessment.
- Protect: access control (AC), data security, awareness training.
- Detect: continuous monitoring, anomaly detection (the Log Monitor agent).
- Respond: incident response plans (the Incident Response agent).
- Recover: backups and recovery testing.

## ISO/IEC 27001 controls (Annex A, 2022)
- A.5 Organizational controls (policies, supplier security).
- A.8 Technological controls (malware protection, logging, vulnerability mgmt).
Vulnerability management (A.8.8) requires identifying, evaluating and
remediating technical vulnerabilities in a timely manner.

## SOC 2 Trust Services Criteria
- Security (Common Criteria): logical access, change management, monitoring.
- Availability, Confidentiality, Processing Integrity, Privacy.
CC7.2 requires monitoring of system components for anomalies; CC7.3/CC7.4 cover
evaluation and response to security incidents.

## Financial-services considerations
Financial systems must enforce strong authentication (MFA), segregation of
duties, encryption of data in transit and at rest, immutable audit trails, and
rapid incident response. Anomalous transfer endpoints (e.g. repeated 401s on
`/api/transfer`) warrant immediate investigation for credential stuffing.
