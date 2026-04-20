wiki_articles = {
    "email_security": [
        {
            "slug": "spf",
            "title": "SPF (Sender Policy Framework)",
            "description": "A DNS-based email authentication protocol that specifies which mail servers are authorized to send email on behalf of a domain."
        },
        {
            "slug": "dkim",
            "title": "DKIM (DomainKeys Identified Mail)",
            "description": "An email authentication standard that uses public-key cryptography to verify that a message was sent and authorized by the owner of a domain."
        },
        {
            "slug": "dmarc",
            "title": "DMARC (Domain-based Message Authentication, Reporting and Conformance)",
            "description": "An email authentication protocol that builds on SPF and DKIM to give domain owners control over how unauthenticated messages are handled and to enable abuse reporting."
        },
        {
            "slug": "arc-authentication",
            "title": "ARC Authentication",
            "description": "Authenticated Received Chain preserves email authentication results across forwarding hops so receiving servers can evaluate the original authentication state."
        },
        {
            "slug": "email-header-analysis",
            "title": "Email Header Analysis",
            "description": "The process of examining RFC 5322 email headers to trace a message's delivery path, verify authentication results, and identify anomalies."
        },
        {
            "slug": "homoglyph-domains",
            "title": "Homoglyph Domains",
            "description": "Domains that substitute visually identical or near-identical Unicode characters to impersonate legitimate domains."
        },
        {
            "slug": "email-spoofing",
            "title": "Email Spoofing",
            "description": "The forgery of email header fields to make a message appear to originate from a sender other than its true source."
        },
        {
            "slug": "link-display-mismatch",
            "title": "Link-Display Mismatch",
            "description": "A phishing technique where the visible anchor text shows a different URL than the actual href destination."
        }
    ],
    "threat_intelligence": [
        {
            "slug": "ioc-enrichment",
            "title": "IOC Enrichment",
            "description": "The process of augmenting raw indicators of compromise with contextual threat intelligence."
        },
        {
            "slug": "attack-surface-management",
            "title": "Attack Surface Management",
            "description": "The continuous process of discovering, inventorying, and reducing an organization's externally exposed digital assets."
        },
        {
            "slug": "indicators-of-compromise",
            "title": "Indicators of Compromise (IOCs)",
            "description": "Observable artifacts that indicate a system or network may have been breached."
        },
        {
            "slug": "threat-intelligence",
            "title": "Threat Intelligence",
            "description": "Evidence-based knowledge about existing or emerging cyber threats."
        },
        {
            "slug": "certificate-transparency",
            "title": "Certificate Transparency",
            "description": "A public logging framework that records all SSL/TLS certificates issued by CAs."
        },
        {
            "slug": "passive-dns",
            "title": "Passive DNS",
            "description": "A historical record of DNS resolutions for domain-to-IP mappings."
        },
        {
            "slug": "whois-lookup",
            "title": "WHOIS Lookup",
            "description": "A protocol for querying domain registration information."
        },
        {
            "slug": "domain-reputation",
            "title": "Domain Reputation",
            "description": "A score or classification assigned to a domain based on historical behavior."
        },
        {
            "slug": "ip-reputation",
            "title": "IP Reputation",
            "description": "A score or classification assigned to an IP based on malicious activity."
        },
        {
            "slug": "threat-actor-profiling",
            "title": "Threat Actor Profiling",
            "description": "The process of identifying and documenting threat group tactics and infrastructure."
        },
        {
            "slug": "dns-security",
            "title": "DNS Security",
            "description": "Practices and technologies for protecting DNS infrastructure."
        },
        {
            "slug": "ssl-tls-certificates",
            "title": "SSL/TLS Certificates",
            "description": "Digital certificates that authenticate server identity and enable encryption."
        },
        {
            "slug": "open-ports",
            "title": "Open Ports",
            "description": "Network ports on a host that are accepting connections."
        },
        {
            "slug": "vulnerability-scanning",
            "title": "Vulnerability Scanning",
            "description": "The automated process of identifying security weaknesses."
        }
    ],
    "forensics": [
        {
            "slug": "phishing-analysis",
            "title": "Phishing Analysis",
            "description": "The forensic examination of suspected phishing emails."
        },
        {
            "slug": "digital-forensics",
            "title": "Digital Forensics",
            "description": "The scientific discipline of identifying, preserving, and presenting digital evidence."
        },
        {
            "slug": "incident-response",
            "title": "Incident Response",
            "description": "The organized approach to detecting, containing, and recovering from security incidents."
        },
        {
            "slug": "timeline-analysis",
            "title": "Timeline Analysis",
            "description": "The process of reconstructing a chronological sequence of events."
        },
        {
            "slug": "log-analysis",
            "title": "Log Analysis",
            "description": "The examination of system and network logs."
        },
        {
            "slug": "malware-analysis",
            "title": "Malware Analysis",
            "description": "The process of examining malicious software behavior and capabilities."
        }
    ],
    "detection_engineering": [
        {
            "slug": "mitre-attack",
            "title": "MITRE ATT&CK Framework",
            "description": "A knowledge base of adversary tactics and techniques based on real-world observations."
        },
        {
            "slug": "sigma-rules",
            "title": "Sigma Rules",
            "description": "A vendor-agnostic open standard for writing detection rules."
        },
        {
            "slug": "yara-rules",
            "title": "YARA Rules",
            "description": "A pattern-matching tool for identifying and classifying malware."
        },
        {
            "slug": "threat-hunting",
            "title": "Threat Hunting",
            "description": "The proactive search for adversary activity that has evaded security controls."
        },
        {
            "slug": "alert-triage",
            "title": "Alert Triage",
            "description": "The process of evaluating and prioritizing security alerts."
        },
        {
            "slug": "siem",
            "title": "SIEM",
            "description": "Security Information and Event Management platform for log analysis."
        },
        {
            "slug": "soar",
            "title": "SOAR",
            "description": "Security Orchestration, Automation, and Response platforms."
        },
        {
            "slug": "detection-as-code",
            "title": "Detection-as-Code",
            "description": "Managing detection rules as version-controlled code."
        },
        {
            "slug": "api-security",
            "title": "API Security",
            "description": "Practices and controls for protecting APIs."
        }
    ],
    "attack_types": [
        {
            "slug": "bec",
            "title": "Business Email Compromise (BEC)",
            "description": "A social engineering attack where adversaries hijack or spoof corporate email accounts."
        },
        {
            "slug": "qr-phishing",
            "title": "QR Phishing (Quishing)",
            "description": "A phishing technique that embeds malicious URLs inside QR codes."
        },
        {
            "slug": "thread-hijacking",
            "title": "Thread Hijacking",
            "description": "An attack where an adversary compromises a mailbox and replies to existing threads."
        },
        {
            "slug": "spear-phishing",
            "title": "Spear Phishing",
            "description": "A targeted phishing attack directed at specific individuals."
        },
        {
            "slug": "credential-harvesting",
            "title": "Credential Harvesting",
            "description": "The theft of usernames and passwords through fake login pages."
        },
        {
            "slug": "typosquatting",
            "title": "Typosquatting",
            "description": "Registering domain names that are deliberate misspellings of legitimate domains."
        },
        {
            "slug": "oauth-phishing",
            "title": "OAuth Phishing",
            "description": "An attack that tricks users into granting malicious OAuth consent."
        },
        {
            "slug": "social-engineering",
            "title": "Social Engineering",
            "description": "Psychological manipulation techniques to deceive people."
        },
        {
            "slug": "ransomware",
            "title": "Ransomware",
            "description": "Malware that encrypts files and demands payment for restoration."
        },
        {
            "slug": "supply-chain-attack",
            "title": "Supply Chain Attack",
            "description": "An attack that compromises a trusted third-party vendor."
        },
        {
            "slug": "watering-hole-attack",
            "title": "Watering Hole Attack",
            "description": "An attack strategy where a website frequently visited by targets is compromised."
        },
        {
            "slug": "brute-force-attack",
            "title": "Brute Force Attack",
            "description": "A method that systematically tries large numbers of passwords."
        },
        {
            "slug": "insider-threat",
            "title": "Insider Threat",
            "description": "A security risk originating from within the organization."
        }
    ]
}

# Article content with full details
wiki_content = {
    "spf": {
        "title": "SPF (Sender Policy Framework)",
        "category": "Email Security",
        "content": """
## What is SPF?

Sender Policy Framework (SPF) is a DNS-based email authentication protocol that allows domain owners to specify which mail servers are authorized to send email on behalf of their domain.

## How It Works

1. Domain owner publishes a TXT record in DNS that lists the authorized sending IP addresses
2. Receiving mail server checks the SPF record before accepting the email
3. If the sending server is not listed, the email may be rejected or marked as spam

## SPF Record Syntax

v=spf1 ip4:192.0.2.0/24 include:_spf.example.com ~all

- v=spf1: Version identifier
- ip4: IPv4 address or network
- include: Includes another domain's SPF record
- ~all: Softfail (recommended)

## Best Practices

- Always use ~all (softfail) instead of -all (fail) initially
- Monitor reports before enforcing strict policy
- Keep DNS lookups under 10 to avoid validation failures
        """
    },
    "dkim": {
        "title": "DKIM (DomainKeys Identified Mail)",
        "category": "Email Security",
        "content": """
## What is DKIM?

DKIM is an email authentication standard that uses public-key cryptography to verify that an email was not altered in transit and was sent by the claimed sender.

## How It Works

1. Sending server signs email headers with a private key
2. Public key is published in DNS as a TXT record
3. Receiving server verifies the signature using the public key

## DKIM Selectors

DKIM uses selectors to differentiate between multiple signing keys:
- default._domainkey.example.com
- google._domainkey.example.com
- selector1._domainkey.example.com

## Common Email Service Providers

- Google Workspace: google._domainkey
- Microsoft 365: selector1._domainkey
- Amazon SES:/amazonses._domainkey
- SendGrid: s1._domainkey
        """
    },
    "dmarc": {
        "title": "DMARC (Domain-based Message Authentication, Reporting and Conformance)",
        "category": "Email Security",
        "content": """
## What is DMARC?

DMARC builds on SPF and DKIM to give domain owners control over how unauthenticated messages are handled and enables aggregate reporting.

## DMARC Policy

- p=none: Monitor only, no action
- p=quarantine: Mark suspicious emails as spam
- p=reject: Reject suspicious emails

## DMARC Reports

- RUA: Aggregate reports (XML)
- RUF: Forensic reports (JSON)

## Example Record

v=DMARC1; p=reject; rua=mailto:dmarc@example.com;ruf=mailto:forensic@example.com;fo=1
        """
    },
    "ioc-enrichment": {
        "title": "IOC Enrichment",
        "category": "Threat Intelligence",
        "content": """
## What is IOC Enrichment?

IOC Enrichment is the process of adding context to raw indicators of compromise (IOCs) like IP addresses, domains, and file hashes.

## Why is it important?

Raw indicators by themselves often lack the context needed for effective incident response. Enrichment provides:
- Reputation scores
- Geographical information
- Associated threat actors
- Malware family names
- Historic behavior

## Sources for Enrichment

Common sources include:
- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Shodan
- GreyNoise
        """
    },
    "mitre-attack": {
        "title": "MITRE ATT&CK Framework",
        "category": "Detection Engineering",
        "content": """
## What is MITRE ATT&CK?

MITRE ATT&CK is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.

## Core Components

- **Tactics**: The 'why' (e.g., Initial Access, Execution, Persistence)
- **Techniques**: The 'how' (e.g., Phishing, Scripting, DLL Injection)
- **Sub-techniques**: More specific descriptions of techniques
- **Groups**: Threat actors and their known campaigns
- **Software**: Tools used by adversaries

## Use Cases

- Adversary emulation
- Red teaming
- Behavioral detection development
- Defensive gap analysis
        """
    },
    "ransomware": {
        "title": "Ransomware",
        "category": "Attack Types",
        "content": """
## What is Ransomware?

Ransomware is a type of malware that encrypts a victim's files. The attacker then demands a ransom from the victim to restore access to the data.

## Modern Trends

- **Double Extortion**: Stealing data before encrypting it and threatening to leak it.
- **Ransomware-as-a-Service (RaaS)**: Affiliate programs where developers lease malware to other criminals.
- **Triple Extortion**: Adding DDoS attacks or contacting the victim's customers/clients.

## Mitigation Strategies

1. Regular offline backups
2. Endpoint protection (EDR)
3. Employee security awareness training
4. Segmenting networks
        """
    },
    "arc-authentication": {
        "title": "ARC Authentication",
        "category": "Email Security",
        "content": """
## What is ARC?

Authenticated Received Chain (ARC) is an email authentication system designed to allow intermediate mail servers (like mailing lists or forwarding services) to sign an email's original authentication results.

## Why is ARC needed?

When an email is forwarded, SPF and DKIM signatures often break because the sending IP changes or the headers/content are modified. This causes the final recipient to see the email as unauthenticated.

## How ARC Works

1. The first server validates SPF, DKIM, and DMARC.
2. It then adds an ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results header.
3. Subsequent servers repeat this process, creating a chain of trust.
4. The final server can verify the entire chain and trust the original results even if SPF/DKIM fail at the final hop.

## ARC Header Components

- **ARC-Authentication-Results (AAR)**: Records the results of the authentication checks.
- **ARC-Message-Signature (AMS)**: A signature of the message.
- **ARC-Seal (AS)**: A signature of the ARC headers themselves.
        """
    },
    "email-header-analysis": {
        "title": "Email Header Analysis",
        "category": "Email Security",
        "content": """
## Introduction to Email Headers

Email headers contain metadata about an email message, including the sender, recipient, path taken through mail servers, and authentication results.

## Critical Headers to Analyze

- **Received**: Shows each mail server the message passed through. Read from bottom to top to trace the path.
- **From / To / CC / BCC**: Basic message routing information.
- **Reply-To**: Often used in phishing to direct replies to an attacker-controlled address.
- **Return-Path**: Where bounce messages are sent. Should match the 'From' domain.
- **X-Mailer / User-Agent**: The software used to send the email.
- **Authentication-Results**: Summary of SPF, DKIM, and DMARC checks.

## Analysis Steps

1. Verify sender authenticity (SPF/DKIM/DMARC).
2. Check for discrepancies between the 'From' address and 'Return-Path'.
3. Examine the 'Received' chain for suspicious IP addresses or hops.
4. Look for anomalous X-headers added by security filters.
        """
    },
    "homoglyph-domains": {
        "title": "Homoglyph Domains",
        "category": "Email Security",
        "content": """
## What are Homoglyph Domains?

Homoglyph domains (or IDN homograph attacks) are domains that use characters from different alphabets that look similar or identical to standard Latin characters to impersonate legitimate domains.

## Examples

- `googIe.com` (using a capital 'I' instead of 'l')
- `аррӏе.com` (using Cyrillic 'а', 'р', and 'е')
- `microsoft.com` (using a zero '0' instead of 'o' - technically a 'typosquat' but often grouped here)

## Punycode

To support these characters in the DNS system, they are converted to Punycode, which starts with `xn--`.

Example: `аррӏе.com` -> `xn--80ak6aa92e.com`

## Detection and Prevention

- Modern browsers often show the Punycode version if they suspect a homograph attack.
- Organizations should monitor for registered 'look-alike' domains.
- Users should be trained to use password managers, which are not fooled by visual similarity.
        """
    },
    "indicators-of-compromise": {
        "title": "Indicators of Compromise (IOCs)",
        "category": "Threat Intelligence",
        "content": """
## What are IOCs?

Indicators of Compromise (IOCs) are digital artifacts or breadcrumbs left behind after a security breach or malicious activity.

## Types of IOCs

1. **Network-based**: IP addresses, domains, URLs, traffic patterns.
2. **Host-based**: File hashes (MD5, SHA256), filenames, registry keys, mutexes.
3. **Behavioral**: Unusual account login times, large data transfers, abnormal command line execution.

## The Pyramid of Pain

David Bianco's 'Pyramid of Pain' ranks IOCs by how difficult they are for an attacker to change:
- **Hash Values**: Trivial for attackers to change (Easy).
- **IP Addresses**: Relatively easy to rotate (Easy).
- **Domain Names**: Slightly harder to change (Simple).
- **Network/Host Artifacts**: Requires significant changes to tools (Annoying).
- **Tools**: Hard to swap out entire toolsets (Challenging).
- **TTPs (Tactics, Techniques, and Procedures)**: Hardest to change as it's the attacker's methodology (Tough).
        """
    },
    "threat-intelligence": {
        "title": "Threat Intelligence",
        "category": "Threat Intelligence",
        "content": """
## What is Threat Intelligence?

Threat Intelligence is evidence-based knowledge, including context, mechanisms, indicators, implications, and actionable advice, about an existing or emerging menace or hazard to assets.

## The Threat Intelligence Cycle

1. **Planning & Direction**: Defining requirements and objectives.
2. **Collection**: Gathering data from various sources (OSINT, commercial, internal).
3. **Processing**: Normalizing and organizing the data.
4. **Analysis & Production**: Turning data into actionable intelligence.
5. **Dissemination**: Sharing intelligence with stakeholders.
6. **Feedback**: Improving the process based on results.

## Types of Intelligence

- **Strategic**: High-level, focused on trends and long-term risk.
- **Operational**: Focused on specific incoming attacks and actor campaigns.
- **Tactical**: Focused on TTPs and real-time indicators (IOCs).
- **Technical**: Technical data such as malware samples or vulnerability details.
        """
    },
    "phishing-analysis": {
        "title": "Phishing Analysis",
        "category": "Forensics",
        "content": """
## Phishing Analysis Workflow

Analyzing a suspected phishing email involves several forensic steps to determine intent, origin, and impact.

## 1. Header Analysis
Check SPF/DKIM/DMARC results. Trace the 'Received' chain to find the true source IP.

## 2. Link Analysis
Defang and examine URLs. Check for link-display mismatches. Analyze redirects and destination page content in a sandbox.

## 3. Attachment Analysis
Calculate hashes of attachments and check reputation (VirusTotal). Perform static and dynamic analysis in a malware sandbox.

## 4. Content Analysis
Look for social engineering triggers: urgency, fear, financial lures, or impersonation of trusted brands.

## 5. Decision & Response
Categorize as 'Phishing', 'Spam', or 'Clean'. Block IOCs at the gateway, purge similar emails from mailboxes, and reset compromised credentials.
        """
    },
    "digital-forensics": {
        "title": "Digital Forensics",
        "category": "Forensics",
        "content": """
## Principles of Digital Forensics

Digital Forensics is the process of identifying, preserving, analyzing, and presenting digital evidence in a legally admissible manner.

## Key Concepts

- **Chain of Custody**: Documenting the history of evidence from collection to court.
- **Evidence Integrity**: Ensuring evidence hasn't been altered (using hashes).
- **Volatility Order**: Collecting evidence starting from the most volatile (RAM) to the least (Hard drives/Backup).

## Forensic Branches

- **Disk Forensics**: Analyzing data on physical storage media.
- **Memory Forensics**: Analyzing volatile RAM for running processes, network connections, and keys.
- **Network Forensics**: Analyzing traffic logs and packet captures (PCAP).
- **Cloud Forensics**: Analyzing logs and artifacts from cloud environments (AWS/Azure/GCP).
- **Mobile Forensics**: Analyzing data from smartphones and tablets.
        """
    },
    "incident-response": {
        "title": "Incident Response",
        "category": "Forensics",
        "content": """
## The Incident Response Lifecycle (NIST)

1. **Preparation**: Establishing tools, team (CSIRT), and playbooks.
2. **Detection & Analysis**: Identifying signs of an incident and assessing its scope.
3. **Containment, Eradication, & Recovery**: Stopping the threat, removing it from the environment, and restoring systems.
4. **Post-Incident Activity**: Conducting a 'Lessons Learned' session and documenting the final report.

## The PICERL Model (SANS)

- **Preparation**
- **Identification**
- **Containment**
- **Eradication**
- **Recovery**
- **Lessons Learned**

## Common IR Artifacts

- Process lists and parent-child relationships.
- Network connection logs.
- Registry persistence mechanisms.
- Event logs (Security, System, PowerShell).
- Prefetch/Shimcache for execution history.
        """
    },
    "yara-rules": {
        "title": "YARA Rules",
        "category": "Detection Engineering",
        "content": """
## What is YARA?

YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples. It uses a rule-based approach to search for patterns in files or process memory.

## Rule Structure

```yara
rule ExampleMalware {
    meta:
        description = "Detects example malware strings"
        author = "Security Researcher"
    strings:
        $s1 = "malicious_function_name"
        $s2 = { E2 34 A1 C2 78 } // Hex string
        $r1 = /https?:\/\/evil\.com\/[a-z]{5}/ // Regex
    condition:
        any of ($s*) and $r1
}
```

## Use Cases

- Malware identification and classification.
- Scanning files during incident response.
- Memory scanning for injected code.
- Email attachment scanning.
        """
    },
    "sigma-rules": {
        "title": "Sigma Rules",
        "category": "Detection Engineering",
        "content": """
## What is Sigma?

Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. It is to logs what YARA is to files and Snort is to network traffic.

## Why Sigma?

Security teams often struggle with different SIEM vendors using proprietary query languages. Sigma allows you to write a rule once and convert it to many targets (Splunk, Elasticsearch, Sentinel, QRadar).

## Rule Structure

```yaml
title: Suspicious Process Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: '/c echo '
    condition: selection
falsepositives:
    - Administrative scripts
level: medium
```

## Conversion

Sigma rules are converted using `sigmac` or `pySigma` into queries specific to your target platform.
        """
    },
    "bec": {
        "title": "Business Email Compromise (BEC)",
        "category": "Attack Types",
        "content": """
## What is BEC?

Business Email Compromise (BEC) is a sophisticated form of cybercrime where attackers use email fraud to target organizations for financial gain. Unlike standard phishing, BEC rarely uses malware, relying instead on social engineering.

## Common BEC Scenarios

1. **CEO Fraud**: Impersonating a high-level executive to request an urgent wire transfer.
2. **Invoice Schemes**: Impersonating a vendor to request payment to a new (attacker-controlled) bank account.
3. **Attorney Impersonation**: Contacting employees while claiming to handle confidential or time-sensitive legal matters.
4. **Data Theft**: Requesting HR or payroll data (like W-2s) for identity theft.

## BEC Prevention

- Implement robust email authentication (SPF, DKIM, DMARC).
- Use multi-factor authentication (MFA) on all email accounts.
- Establish out-of-band verification procedures for any financial requests.
- Employee awareness training on social engineering tactics.
        """
    }
}

