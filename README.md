# Darwin SPF Email Authentication SOC Investigation

## Overview

This project documents a simulated Security Operations Center (SOC) investigation of a suspicious email claiming to originate from PayPal.

The investigation focused on SPF email authentication, DNS analysis, reverse DNS lookups, IP reputation, blacklist analysis, and validation of authorized email-sending infrastructure.

The suspicious source IP was compared against the SPF records associated with `paypal.com`, SendGrid, and Pardot to determine whether the source was authorized to send email on behalf of the claimed domain.

---

## Environment

* MXToolbox SuperTool
* SPF Record Lookup
* DNS / TXT Records
* Reverse DNS / PTR Lookup
* IP Blacklist Lookup
* CIDR / IP Range Analysis
* Web Browser
* GitHub Documentation

---

## Skills Demonstrated

* SOC Alert Triage
* Phishing Investigation
* Email Security Analysis
* SPF Authentication Analysis
* DNS Investigation
* Reverse DNS Analysis
* IP Reputation Analysis
* IOC Analysis
* Email Spoofing Detection
* Incident Documentation
* Threat Analysis

---

## Investigation Scenario

A simulated suspicious email was reported with the following information:

* **Claimed Sender:** `security@paypal.com`
* **Claimed Domain:** `paypal.com`
* **Source IP:** `185.220.101.45`
* **Alert Type:** Suspicious Email
* **Investigation Type:** Phishing / Email Authentication
* **Analyst Role:** Tier 1 SOC Analyst

The objective was to determine whether the source IP was authorized to send email for the claimed PayPal domain.

---

## Step 1 - Analyze PayPal SPF Record

The SPF record for `paypal.com` was retrieved using MXToolbox.

The record contained multiple `include` mechanisms referencing additional authorized email infrastructure.

```text
include:pp._spf.paypal.com
include:3ph1._spf.paypal.com
include:3ph2._spf.paypal.com
include:3ph3._spf.paypal.com
include:3ph4._spf.paypal.com
include:sendgrid.net
include:aspmx.pardot.com
~all
```

The main SPF record ends with `~all`, indicating a SoftFail policy when a sending IP does not match an authorized SPF mechanism.

### Screenshot


![PayPal SPF Record](screenshots/01-paypal-spf.png)

---

## Step 2 - Reverse DNS Investigation

The suspicious IP was investigated using a reverse DNS lookup.

```text
185.220.101.45
```

The PTR record returned:

```text
tor-exit-45.for-privacy.net
```

The hostname indicates that the IP is associated with Tor exit infrastructure.

Tor usage alone does not prove malicious activity, but it increases the risk of an email claiming to originate from a trusted financial organization.

### Screenshot


![Reverse DNS Investigation](screenshots/02-reverse-dns.png)

---

## Step 3 - IP Reputation Analysis

The suspicious source IP was checked against approximately 60 known blacklist services.

MXToolbox reported that the IP was listed multiple times.

Notable listings included:

* DAN TOR
* DAN TOREXIT
* Spamhaus ZEN
* RATS Spam
* IMP SPAM
* Hostkarma Black
* Abusix Mail Intelligence Blacklist

This provided additional evidence that the source IP should be treated as suspicious.

### Screenshot

![IP Blacklist Analysis](screenshots/03-blacklist-results.png)

---

## Step 4 - Analyze PayPal Authorized SPF Infrastructure

The SPF record for:

```text
pp._spf.paypal.com
```

was investigated.

The record contained authorized PayPal IP ranges including:

```text
173.0.84.224/27
66.211.170.85/30
66.211.170.88/29
173.224.165.0/26
173.224.166.48/28
173.0.94.244/30
173.224.161.128/25
173.0.84.0/29
```

The suspicious IP `185.220.101.45` did not match the reviewed authorized ranges.

### Screenshot

![PayPal PP SPF Record](screenshots/04-paypal-pp-spf.png)

---

## Step 5 - Analyze PayPal 3PH1 SPF Record

The following SPF record was reviewed:

```text
3ph1._spf.paypal.com
```

The suspicious source IP did not match the reviewed authorized addresses or networks.

### Screenshot


![PayPal 3PH1 SPF Record](screenshots/05-paypal-3ph1.png)
---

## Step 6 - Analyze PayPal 3PH2 SPF Record

The following SPF record was reviewed:

```text
3ph2._spf.paypal.com
```

The source IP `185.220.101.45` did not match the reviewed authorized IP infrastructure.

### Screenshot

![PayPal 3PH2 SPF Record](screenshots/06-paypal-3ph2.png)

---

## Step 7 - Analyze PayPal 3PH3 SPF Record

The following SPF record was investigated:

```text
3ph3._spf.paypal.com
```

The suspicious source IP did not match the reviewed authorized IP ranges.

### Screenshot


![PayPal 3PH3 SPF Record](screenshots/07-paypal-3ph3.png)

---

## Step 8 - Analyze PayPal 3PH4 SPF Record

The following SPF record was investigated:

```text
3ph4._spf.paypal.com
```

The suspicious source IP did not match the reviewed authorized infrastructure.

### Screenshot

![PayPal 3PH4 SPF Record](screenshots/08-paypal-3ph4.png)

---

## Step 9 - SendGrid SPF Investigation

The main PayPal SPF record included:

```text
include:sendgrid.net
```

The SendGrid SPF record was reviewed to determine whether the suspicious IP was part of SendGrid's authorized infrastructure.

The IP `185.220.101.45` did not match the reviewed SendGrid networks.

### Screenshot

![SendGrid SPF Investigation](screenshots/09-sendgrid-spf.png)

---

## Step 10 - Pardot SPF Investigation

The PayPal SPF record also included:

```text
include:aspmx.pardot.com
```

The Pardot SPF record referenced another SPF record:

```text
include:et._spf.pardot.com
```

This required an additional SPF lookup.

### Screenshot

![Pardot SPF Investigation](screenshots/10-pardot-spf.png)
---

## Step 11 - Pardot Authorized IP Analysis

The following record was investigated:

```text
et._spf.pardot.com
```

Authorized networks included:

```text
198.245.81.0/24
136.147.176.0/24
13.111.0.0/16
136.147.182.0/24
136.147.135.0/24
199.122.123.0/24
```

The suspicious source IP `185.220.101.45` did not match the reviewed Pardot infrastructure.

### Screenshot

![Pardot Authorized IP Analysis](screenshots/11-pardot-et-spf.png)
---

## Indicators of Compromise

| Indicator                     | Type           | Finding                   |
| ----------------------------- | -------------- | ------------------------- |
| `185.220.101.45`              | IPv4 Address   | Suspicious source IP      |
| `tor-exit-45.for-privacy.net` | PTR Record     | Tor exit infrastructure   |
| `security@paypal.com`         | Claimed Sender | Possible spoofed identity |
| `paypal.com`                  | Domain         | Claimed sender domain     |
| Multiple blacklist listings   | Reputation     | Elevated risk             |

---

## Investigation Findings

The investigation identified several indicators that increased the risk associated with the simulated email:

* The source IP was associated with Tor exit infrastructure.
* The IP appeared on multiple blacklist services.
* The source IP did not match the reviewed PayPal SPF ranges.
* The source IP did not match the reviewed SendGrid SPF infrastructure.
* The source IP did not match the reviewed Pardot SPF infrastructure.
* The claimed sender identity was inconsistent with the reviewed authorized email infrastructure.

---

## SOC Analyst Verdict

**Classification:** Likely Phishing / Email Spoofing

**Severity:** High

**Confidence:** High

The simulated email should be treated as suspicious because the source IP was inconsistent with the reviewed SPF-authorized infrastructure for the claimed sender domain.

The Tor exit-node association and multiple blacklist listings provided additional supporting indicators.

---

## Recommended Response Actions

* Quarantine the suspicious email.
* Search the SIEM for additional activity involving the source IP.
* Identify other users who may have received similar messages.
* Review email headers for SPF, DKIM, and DMARC results.
* Extract and investigate URLs, domains, and attachments.
* Block or monitor malicious indicators according to organizational policy.
* Document the investigation in the incident management system.
* Escalate the incident if additional signs of compromise are discovered.

---

## MITRE ATT&CK Mapping

### T1566 - Phishing

Adversaries may send malicious emails in an attempt to gain initial access or convince users to interact with malicious content.

### T1036 - Masquerading

Adversaries may attempt to impersonate trusted organizations or users to make malicious activity appear legitimate.

---

## Investigation Workflow

```text
Suspicious Email Reported
        |
        v
Identify Claimed Sender
        |
        v
Extract Source IP
        |
        v
Review SPF Record
        |
        v
Reverse DNS Lookup
        |
        v
IP Reputation Check
        |
        v
Analyze SPF Includes
        |
        v
Compare Authorized IP Ranges
        |
        v
Correlate Evidence
        |
        v
Classify Incident
        |
        v
Document and Escalate
```

---

## Key Takeaways

This lab demonstrated how a Tier 1 SOC analyst can investigate suspicious email activity by combining SPF authentication analysis with DNS and threat intelligence.

The investigation also demonstrated why SPF should not be evaluated by itself. Email investigations should correlate multiple sources of evidence including:

* SPF
* DKIM
* DMARC
* Reverse DNS
* IP reputation
* Email headers
* URLs
* Attachments
* SIEM telemetry

---

## Disclaimer

This project is a simulated cybersecurity investigation created for educational and portfolio purposes.

The suspicious email scenario was created for defensive-security training and does not represent an actual security incident involving PayPal, SendGrid, Pardot, or any other referenced organization.

---

## Author

**Darwin Brown Jr.**

SOC Analyst / Cybersecurity Analyst Portfolio Project
