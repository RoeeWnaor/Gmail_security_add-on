# Gmail Security Add-on

A Gmail Add-on for detecting potentially malicious emails using a multi-layer security pipeline.

## Architecture
The add-on analyzes each opened email using a layered security approach:

1. **Global Analysis**
   - Sender authentication (SPF / DKIM / DMARC)
   - Reply-To consistency checks
   - Domain reputation via external intelligence

2. **Macro Analysis**
   - Email structure inspection
   - Link density analysis
   - Detection of suspicious data patterns

3. **Micro Analysis**
   - Deep inspection of hyperlinks
   - URL deception detection (visible text vs actual destination)
   - Brand impersonation heuristics

Each layer contributes to a final risk score (0–100) with a clear and explainable verdict.

## Technologies & APIs
- Google Workspace Gmail Add-on (Apps Script)
- GmailApp, CardService, PropertiesService
- IPQualityScore (external domain reputation API)

## Implemented Features
- Risk scoring with SAFE / SUSPICIOUS / HIGH RISK verdict
- Explainable findings per email
- SPF/DKIM/DMARC authentication analysis
- Reply-To mismatch detection
- External reputation enrichment
- URL deception detection
- Brand impersonation heuristics
- User-managed blacklist
- Scan history and sender/domain statistics
- Configurable security thresholds and settings

## Limitations
- Attachment analysis was not implemented
- Rule-based heuristics only (no machine learning models)
- Domain parsing uses heuristic-based logic (no full public suffix list)
- External reputation checks depend on third-party API availability

## No
