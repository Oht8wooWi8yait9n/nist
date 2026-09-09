# NIST Cybersecurity & Computing Standards Sitemap for Onyx

Automated discovery, validation, and flat XML sitemap pipeline for official **NIST Cybersecurity & Computing Standards** published by the National Institute of Standards and Technology (NIST) via the Computer Security Resource Center (CSRC) and NVLpubs.

---

## 🚀 Onyx Ingestion URLs

Add a new **Web Connector** in the Onyx Admin Console using either of the following raw GitHub URLs:

### Option 1: Final Approved Standards (Recommended)
Contains all canonical, officially approved NIST standards (**629 direct PDFs**). This is the highest-signal compliance collection for day-to-day security and engineering queries.

```text
https://raw.githubusercontent.com/Oht8wooWi8yait9n/nist/master/nist_standards_final.xml
```

### Option 2: All Standards + Active Drafts (Extended)
Includes all final approved standards plus active **Initial Public Drafts (IPD)** and **Final Public Drafts (FPD)** (**1,372 direct PDFs**) to track upcoming revisions.

```text
https://raw.githubusercontent.com/Oht8wooWi8yait9n/nist/master/nist_standards_all.xml
```

---

## 📚 Standards Series Covered

| Series | Scope & Key Documents |
|---|---|
| **NIST SP 800** | **Computer Security**: SP 800-53 (Security & Privacy Controls), SP 800-171 (CUI), SP 800-37 (RMF), SP 800-30 (Risk Assessment), SP 800-63 (Digital Identity), SP 800-161 (Supply Chain), SP 800-207 (Zero Trust Architecture), etc. |
| **NIST SP 1800** | **Cybersecurity Practice Guides**: Applied implementations for Zero Trust, Cloud Identity, Mobile Security, Access Rights Management, Securing Telehealth, etc. |
| **NIST SP 500** | **Computer Systems Technology**: Software assurance, cloud computing reference architectures, forensic computing standards. |
| **NIST FIPS** | **Federal Information Processing Standards**: FIPS 140-3 (Cryptographic Module Validation), FIPS 197 (AES), FIPS 201-3 (Personal Identity Verification / PIV), FIPS 199 / 200 (Minimum Security Requirements). |
| **NIST IR (NISTIR)** | **Interagency / Internal Reports**: Technical research, hardware security, post-quantum cryptography evaluations, vulnerability scoring standards. |
| **NIST CSWP** | **Cybersecurity White Papers**: Modern applied guidance on SBOM (Software Bill of Materials), DevSecOps, and continuous diagnostics. |
| **NIST AI** | **Artificial Intelligence Frameworks**: AI Risk Management Framework (AI RMF 1.0), Generative AI Risk Profiles, AI Red Teaming guidelines. |

---

## ⚙️ Onyx Web Connector Settings

When creating the connector in Onyx:
* **Connector Type**: `Web`
* **Base URL / Sitemap URL**:
  `https://raw.githubusercontent.com/Oht8wooWi8yait9n/nist/master/nist_standards_final.xml`
* **Web Connector Mode**: `Sitemap`
* **Auto-Indexing Frequency**: Every 7 days (weekly)
* **Expected Ingestion Time**: ~5 to 10 minutes (629 PDFs)

---

## 🔄 Automated Updates

This repository is automatically updated every Monday at 05:00 UTC via GitHub Actions:
- Crawls CSRC for newly published final standards, errata, and public drafts.
- Resolves direct canonical PDF URLs on `nvlpubs.nist.gov`.
- Validates XML structure and commits updates with `[skip ci]`.
