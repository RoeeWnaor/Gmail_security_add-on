# Gmail Security Add-on

A Gmail Add-on for identifying potentially malicious emails using a layered, explainable security analysis pipeline.

The add-on analyzes each opened email directly inside Gmail and provides a clear risk score, verdict, and human-readable explanations to help users quickly assess email safety.

---

## How It Works

The system follows a **multi-layer security pipeline**, inspired by real-world email security products:

### 1. Global Analysis
Focuses on sender identity and trust signals:
- SPF / DKIM / DMARC authentication checks
- Reply-To consistency validation
- Domain reputation enrichment via external intelligence
- Sender and domain history tracking

### 2. Macro Analysis
Examines the overall structure of the email:
- Link density vs. content size
- Suspicious numeric patterns (e.g. financial data heuristics)
- Structural signals commonly seen in phishing campaigns

### 3. Micro Analysis
Performs deep inspection of email content:
- Hyperlink inspection
- Detection of URL deception (visible text vs. actual destination)
- Brand impersonation and typosquatting heuristics

Each layer contributes to a final **risk score (0–100)** and a clear verdict:
**SAFE**, **SUSPICIOUS**, or **HIGH RISK**.

---

## Key Features

- 🔐 Layered email security analysis (Global → Macro → Micro)
- 📊 Explainable risk scoring with detailed findings
- 🌐 External domain reputation enrichment
- 🔁 Reply-To mismatch detection
- 🔗 URL deception and phishing heuristics
- 🚫 User-managed sender blacklist
- 🕒 Sender and domain scan history
- ⚙️ Configurable security thresholds and settings
- 📩 Fully integrated Gmail Add-on UI

---

## Technology Stack

- Google Workspace Gmail Add-ons (Apps Script, V8)
- GmailApp & CardService for message access and UI
- PropertiesService for user-level persistence
- External reputation API (domain intelligence)

---

## Screenshots

> Screenshots can be added here to demonstrate the add-on UI and analysis output.

---

## Future Improvements

- Attachment inspection and file-type analysis
- Public Suffix List–based domain parsing
- Machine learning–based scoring models
- Cross-user reputation aggregation
- Admin and organization-wide policies

---

## Disclaimer

This project is intended for educational and demonstrational purposes and is not a replacement for enterprise-grade email security solutions.
