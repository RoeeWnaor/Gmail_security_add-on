
const APP_NAME = "Roee_Gmail_Safer";

//  Defaults (can be overridden by User Properties) 
const DEFAULTS = {
  ENABLE_EXTERNAL_INTEL: true,
  LINK_DENSITY_THRESHOLD: 0.15, // links/words
  HIGH_RISK_THRESHOLD: 80,
  SUSPICIOUS_THRESHOLD: 40,
  REPLY_TO_MISMATCH_SCORE: 35,
  UNAUTHENTICATED_SCORE: 20,
  HIGH_LINK_DENSITY_SCORE: 25,
  POSSIBLE_CC_SCORE: 45,
  URL_DECEPTION_SCORE: 70,
  BRAND_IMPERSONATION_SCORE: 80,
  GLOBAL_THREAT_SCORE: 85,
  HIGH_REP_SCORE: 40,
  YOUNG_DOMAIN_SCORE: 35,
  TRUST_REDUCTION_MAX: 30, // max points to reduce
};

//  Entry point (Gmail Add-on trigger) 
function buildAddOn(e) {
  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);

  const analysis = runSecurityPipeline(message);
  return [createMainCard(analysis, message, messageId)];
}

//  Actions 
function addToBlacklist(e) {
  const senderEmail = (e.parameters && e.parameters.senderEmail) || "";
  if (!senderEmail) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Missing sender email."))
      .build();
  }
  PropertiesService.getUserProperties().setProperty(`BL:${senderEmail.toLowerCase()}`, "1");
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Sender blocked (blacklist)."))
    .build();
}

function removeFromBlacklist(e) {
  const senderEmail = (e.parameters && e.parameters.senderEmail) || "";
  if (!senderEmail) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Missing sender email."))
      .build();
  }
  PropertiesService.getUserProperties().deleteProperty(`BL:${senderEmail.toLowerCase()}`);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Sender removed from blacklist."))
    .build();
}

function openSettings(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(createSettingsCard()))
    .build();
}

function saveSettings(e) {
  const params = (e && e.parameters) || {};
  const up = PropertiesService.getUserProperties();

  // ENABLE_EXTERNAL_INTEL: "true"/"false"
  if (typeof params.enableExternalIntel === "string") {
    up.setProperty("SET:ENABLE_EXTERNAL_INTEL", params.enableExternalIntel);
  }

  // LINK_DENSITY_THRESHOLD
  if (typeof params.linkDensityThreshold === "string") {
    const v = parseFloat(params.linkDensityThreshold);
    if (!Number.isNaN(v) && v > 0 && v < 1) {
      up.setProperty("SET:LINK_DENSITY_THRESHOLD", String(v));
    }
  }

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Settings saved."))
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

function rescanMessage(e) {
  const messageId = (e.parameters && e.parameters.messageId) || "";
  if (!messageId) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Missing messageId."))
      .build();
  }
  const message = GmailApp.getMessageById(messageId);
  const analysis = runSecurityPipeline(message);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(createMainCard(analysis, message, messageId)))
    .build();
}

//  Core Pipeline 
function runSecurityPipeline(message) {
  const settings = getSettings();
  let score = 0;
  let findings = [];

  const fromRaw = (message.getFrom() || "").toLowerCase();
  const cleanFromEmail = extractEmail(fromRaw);
  const fromDomain = getDomain(cleanFromEmail);

  const replyToRaw = safeGetReplyTo_(message);
  const cleanReplyToEmail = replyToRaw ? extractEmail(replyToRaw.toLowerCase()) : "";
  const replyToDomain = cleanReplyToEmail ? getDomain(cleanReplyToEmail) : "";

  // Stage 0: Blacklist 
  if (isBlacklisted(cleanFromEmail)) {
    // Record scan history even for blacklisted
    recordScanHistory_(cleanFromEmail, fromDomain, 100, ["❌ BLOCKED: Personal Blacklist"]);
    return { finalScore: 100, findings: ["❌ BLOCKED: Personal Blacklist"], senderEmail: cleanFromEmail };
  }

  // Stage 1: Sender & Headers 
  // 1.1 Authentication check (SPF/DKIM) - more robust
  const auth = checkAuthentication(message);
  if (auth.isAuthenticated) {
    findings.push(`✅ Authenticated Sender (${auth.details})`);
  } else {
    findings.push("⚠️ Unauthenticated Sender (SPF/DKIM not verified)");
    score += DEFAULTS.UNAUTHENTICATED_SCORE;
  }

  // 1.2 Reply-To mismatch rule (classic phishing signal)
  if (cleanReplyToEmail) {
    const fromRoot = extractRegistrableCore(fromDomain);
    const replyRoot = extractRegistrableCore(replyToDomain);
    if (fromRoot && replyRoot && fromRoot !== replyRoot) {
      score += DEFAULTS.REPLY_TO_MISMATCH_SCORE;
      findings.push(`⚠️ Reply-To mismatch: replies go to a different domain (${replyToDomain})`);
    } else {
      findings.push("✅ Reply-To is consistent with sender domain");
    }
  } else {
    findings.push("ℹ️ No Reply-To header (normal in many emails)");
  }

  // 1.3 Brand impersonation heuristic (typosquatting)
  const identity = analyzeSenderIdentity(cleanFromEmail);
  score += identity.score;
  findings = findings.concat(identity.findings);

  //  Stage 2: External Intelligence 
  let globalRep = { score: 0, findings: [], isTrusted: false, skipped: true };
  if (settings.enableExternalIntel && fromDomain) {
    globalRep = checkGlobalReputation(fromDomain);
    score += globalRep.score;
    findings = findings.concat(globalRep.findings);
  } else {
    findings.push("ℹ️ External intelligence disabled (Settings)");
  }

  // Stage 3: Macro Analysis 
  const macro = analyzeEmailStructure(message, settings);
  score += macro.score;
  findings = findings.concat(macro.findings);

  // Stage 4: Micro Analysis 
  const micro = analyzeEmailContentMicro(message);
  score += micro.score;
  findings = findings.concat(micro.findings);

  //  Stage 5: Trust adjustment (less aggressive) 
  if (auth.isAuthenticated && globalRep.isTrusted && score > 0) {
    const reduction = Math.min(DEFAULTS.TRUST_REDUCTION_MAX, Math.round(score * 0.25));
    score = Math.max(0, score - reduction);
    findings.push(`ℹ️ Risk reduced by ${reduction} (authenticated + trusted reputation)`);
  }

  const finalScore = clampInt(Math.round(score), 0, 100);

  //  Stage 6: History / stats 
  appendHistoryFindings_(findings, cleanFromEmail, fromDomain);
  recordScanHistory_(cleanFromEmail, fromDomain, finalScore, findings);

  return { finalScore, findings, senderEmail: cleanFromEmail };
}

//  External Intelligence Layer 
function checkGlobalReputation(domain) {
  const apiKey = PropertiesService.getScriptProperties().getProperty("IPQS_API_KEY");
  if (!apiKey) {
    return { score: 0, findings: ["⚠️ External intelligence unavailable (missing IPQS_API_KEY in Script Properties)"], isTrusted: false, skipped: true };
  }

  const url = "https://www.ipqualityscore.com/api/json/url/" + encodeURIComponent(apiKey) + "/" + encodeURIComponent(domain);

  try {
    const response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    const text = response.getContentText() || "";
    const data = JSON.parse(text);

    if (!data || !data.success) {
      return { score: 0, findings: ["⚠️ External intelligence unavailable (API error)"], isTrusted: false };
    }

    let s = 0;
    let f = [];

    if (data.phishing || data.malware) {
      s += DEFAULTS.GLOBAL_THREAT_SCORE;
      f.push("❌ GLOBAL THREAT: Domain flagged for phishing/malware");
    } else if (typeof data.risk_score === "number" && data.risk_score > 70) {
      s += DEFAULTS.HIGH_REP_SCORE;
      f.push("⚠️ High risk reputation (external intel)");
    }

    // Domain age heuristic (very rough)
    if (data.domain_age && typeof data.domain_age.human === "string") {
      const human = data.domain_age.human.toLowerCase();
      if (human.includes("day") || human.includes("days")) {
        s += DEFAULTS.YOUNG_DOMAIN_SCORE;
        f.push("⚠️ Young domain alert (age in days)");
      }
    }

    if (f.length === 0) f.push("✅ Clean global reputation (external intel)");
    const isTrusted = (typeof data.risk_score === "number") ? (data.risk_score < 40) : false;

    return { score: s, findings: f, isTrusted };
  } catch (e) {
    return { score: 0, findings: ["⚠️ External intelligence check failed"], isTrusted: false };
  }
}

//  Macro Analysis 
function analyzeEmailStructure(message, settings) {
  const plain = message.getPlainBody() || "";
  const words = plain.trim() ? plain.trim().split(/\s+/).length : 0;

  // Count links more robustly: look for <a ... href= ...> OR http(s) occurrences in plain
  const html = message.getBody() || "";
  const aLinks = (html.match(/<a\s+[^>]*href=/gi) || []).length;
  const plainLinks = (plain.match(/\bhttps?:\/\/\S+/gi) || []).length;
  const links = Math.max(aLinks, plainLinks);

  let s = 0;
  let f = [];

  if (words > 0) {
    const density = links / words;
    if (density > settings.linkDensityThreshold) {
      s += DEFAULTS.HIGH_LINK_DENSITY_SCORE;
      f.push(`⚠️ High link density detected (${density.toFixed(2)} links/word)`);
    }
  }

  // Simple CC-like pattern (heuristic)
  if (/\b(?:\d[ -]*?){13,16}\b/.test(plain)) {
    s += DEFAULTS.POSSIBLE_CC_SCORE;
    f.push("⚠️ Possible financial data pattern detected");
  }

  return { score: s, findings: f };
}

//  Micro Analysis 
function analyzeEmailContentMicro(message) {
  const html = message.getBody() || "";
  const linkRegex = /<a\s+(?:[^>]*?\s+)?href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;

  let s = 0;
  let f = [];

  let m;
  while ((m = linkRegex.exec(html)) !== null) {
    const actualUrl = (m[1] || "").trim();
    const visibleHtml = (m[2] || "");
    const visibleText = visibleHtml.replace(/<[^>]*>/g, "").trim();

    // If visible text looks like a domain and doesn't match actual hostname core -> deception
    const visibleDomainCandidate = extractDomainFromText(visibleText);
    const actualHost = safeHostnameFromUrl_(actualUrl);

    if (visibleDomainCandidate && actualHost) {
      const visibleCore = extractRegistrableCore(visibleDomainCandidate);
      const actualCore = extractRegistrableCore(actualHost);

      if (visibleCore && actualCore && visibleCore !== actualCore) {
        s = Math.max(s, DEFAULTS.URL_DECEPTION_SCORE);
        f.push(`⚠️ URL deception: visible "${visibleDomainCandidate}" points to "${actualHost}"`);
      }
    }
  }

  return { score: s, findings: f };
}

//  Identity Layer 
function analyzeSenderIdentity(fromEmail) {
  const domain = getDomain(fromEmail);
  const core = extractRegistrableCore(domain);

  const brands = ["paypal", "google", "microsoft", "apple", "amazon", "linkedin"];
  for (const b of brands) {
    if (core === b) return { score: 0, findings: [] };

    const dist = getLevenshteinDistance(core, b);
    const sim = 1 - (dist / Math.max(core.length, b.length));
    if (sim >= 0.85) {
      return { score: DEFAULTS.BRAND_IMPERSONATION_SCORE, findings: [`⚠️ Impersonation warning: domain looks similar to "${b}"`] };
    }
  }
  return { score: 0, findings: [] };
}

//  UI 
function createMainCard(analysis, message, messageId) {
  const from = message.getFrom() || "";
  const subject = message.getSubject() || "(no subject)";

  const verdict = getVerdict_(analysis.finalScore);
  const header = CardService.newCardHeader()
    .setTitle(APP_NAME)
    .setSubtitle(subject);

  const section = CardService.newCardSection()
    .setHeader(`Verdict: ${verdict.label}`)
    .addWidget(CardService.newTextParagraph().setText(`Risk Score: **${analysis.finalScore}/100**`))
    .addWidget(CardService.newTextParagraph().setText(`From: ${escapeHtml_(from)}`))
    .addWidget(CardService.newDivider());

  analysis.findings.forEach(line => {
    section.addWidget(CardService.newTextParagraph().setText(escapeHtml_(line)));
  });

  const footer = CardService.newFixedFooter()
    .setPrimaryButton(
      CardService.newTextButton()
        .setText("ADD TO BLACKLIST")
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("addToBlacklist")
            .setParameters({ senderEmail: analysis.senderEmail })
        )
    )
    .setSecondaryButton(
      CardService.newTextButton()
        .setText("SETTINGS")
        .setOnClickAction(CardService.newAction().setFunctionName("openSettings"))
    );

  // Add “Rescan” button inside section
  section.addWidget(CardService.newDivider());
  section.addWidget(
    CardService.newTextButton()
      .setText("RESCAN")
      .setOnClickAction(CardService.newAction().setFunctionName("rescanMessage").setParameters({ messageId }))
  );

  // If blacklisted already show remove option
  if (isBlacklisted(analysis.senderEmail)) {
    section.addWidget(
      CardService.newTextButton()
        .setText("REMOVE FROM BLACKLIST")
        .setOnClickAction(CardService.newAction().setFunctionName("removeFromBlacklist").setParameters({ senderEmail: analysis.senderEmail }))
    );
  }

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .setFixedFooter(footer)
    .build();
}

function createSettingsCard() {
  const settings = getSettings();

  const header = CardService.newCardHeader()
    .setTitle(`${APP_NAME} Settings`)
    .setSubtitle("Basic configuration");

  const section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("Toggle external intelligence checks and adjust thresholds."));

  const enableExternalIntel = CardService.newSelectionInput()
    .setType(CardService.SelectionInputType.CHECK_BOX)
    .setFieldName("enableExternalIntel")
    .addItem("Enable External Intelligence (IPQS)", "true", settings.enableExternalIntel);

  const linkDensity = CardService.newTextInput()
    .setFieldName("linkDensityThreshold")
    .setTitle("Link density threshold (0-1)")
    .setValue(String(settings.linkDensityThreshold));

  const saveBtn = CardService.newTextButton()
    .setText("SAVE")
    .setOnClickAction(
      CardService.newAction()
        .setFunctionName("saveSettings")
        .setParameters({
          enableExternalIntel: String(settings.enableExternalIntel),
          linkDensityThreshold: String(settings.linkDensityThreshold),
        })
    );

  // Workaround: SelectionInput values are only submitted via form inputs,
  // but Apps Script Add-ons are picky. We'll also let user type if needed.
  section
    .addWidget(enableExternalIntel)
    .addWidget(linkDensity)
    .addWidget(saveBtn);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

//  Authentication 
function checkAuthentication(message) {
  const raw = (message.getRawContent() || "");

  // Try to find Authentication-Results header
  const authLine = extractHeaderLine_(raw, "Authentication-Results");
  if (!authLine) {
    // fallback: rough check in raw
    const low = raw.toLowerCase();
    const spfPass = low.includes("spf=pass");
    const dkimPass = low.includes("dkim=pass");
    const isAuthenticated = spfPass || dkimPass;
    return { isAuthenticated, details: isAuthenticated ? "spf/dkim pass (fallback)" : "unknown" };
  }

  const low = authLine.toLowerCase();
  const spfPass = /spf\s*=\s*pass/.test(low);
  const dkimPass = /dkim\s*=\s*pass/.test(low);
  const dmarcPass = /dmarc\s*=\s*pass/.test(low);

  const details = [
    spfPass ? "SPF pass" : "SPF ?",
    dkimPass ? "DKIM pass" : "DKIM ?",
    dmarcPass ? "DMARC pass" : "DMARC ?",
  ].join(", ");

  return { isAuthenticated: (spfPass || dkimPass || dmarcPass), details };
}

//  History / Stats 
function recordScanHistory_(senderEmail, domain, finalScore, findings) {
  const up = PropertiesService.getUserProperties();
  const now = new Date().toISOString();

  // Message-level history omitted (no messageId inside pipeline here),
  // but we keep sender+domain stats.
  if (senderEmail) {
    incrementCounter_(up, `STAT:SENDER:${senderEmail}`);
    up.setProperty(`LAST:SENDER:${senderEmail}`, JSON.stringify({ at: now, score: finalScore }));
  }
  if (domain) {
    incrementCounter_(up, `STAT:DOMAIN:${domain}`);
    up.setProperty(`LAST:DOMAIN:${domain}`, JSON.stringify({ at: now, score: finalScore }));
  }

  // store last scan summary
  up.setProperty("LAST:SCAN", JSON.stringify({
    at: now,
    senderEmail,
    domain,
    score: finalScore,
    top: (findings || []).slice(0, 5),
  }));
}

function appendHistoryFindings_(findings, senderEmail, domain) {
  const up = PropertiesService.getUserProperties();

  if (senderEmail) {
    const c = parseInt(up.getProperty(`STAT:SENDER:${senderEmail}`) || "0", 10);
    if (c > 0) findings.push(`ℹ️ Sender seen before: ${c} previous scans`);
    const last = up.getProperty(`LAST:SENDER:${senderEmail}`);
    if (last) {
      const obj = safeJsonParse_(last);
      if (obj && obj.at) findings.push(`ℹ️ Last sender scan: ${obj.at} (score ${obj.score})`);
    }
  }

  if (domain) {
    const c = parseInt(up.getProperty(`STAT:DOMAIN:${domain}`) || "0", 10);
    if (c > 0) findings.push(`ℹ️ Domain seen before: ${c} previous scans`);
  }
}

function incrementCounter_(up, key) {
  const cur = parseInt(up.getProperty(key) || "0", 10);
  up.setProperty(key, String(cur + 1));
}

//  Settings 
function getSettings() {
  const up = PropertiesService.getUserProperties();

  const enableExternalIntel = (up.getProperty("SET:ENABLE_EXTERNAL_INTEL") ?? String(DEFAULTS.ENABLE_EXTERNAL_INTEL)) === "true";

  const linkDensityThresholdRaw = up.getProperty("SET:LINK_DENSITY_THRESHOLD");
  const linkDensityThreshold = linkDensityThresholdRaw ? parseFloat(linkDensityThresholdRaw) : DEFAULTS.LINK_DENSITY_THRESHOLD;

  return {
    enableExternalIntel,
    linkDensityThreshold: (!Number.isNaN(linkDensityThreshold) && linkDensityThreshold > 0 && linkDensityThreshold < 1)
      ? linkDensityThreshold
      : DEFAULTS.LINK_DENSITY_THRESHOLD
  };
}

// Helpers 
function isBlacklisted(senderEmail) {
  if (!senderEmail) return false;
  const up = PropertiesService.getUserProperties();
  return up.getProperty(`BL:${senderEmail.toLowerCase()}`) === "1";
}

function extractEmail(fromField) {
  if (!fromField) return "";
  const m = fromField.match(/<([^>]+)>/);
  const email = (m ? m[1] : fromField).trim();
  // remove surrounding quotes if present
  return email.replace(/^"+|"+$/g, "");
}

function getDomain(email) {
  const parts = (email || "").split("@");
  return parts.length === 2 ? parts[1].trim().toLowerCase() : "";
}

/**
 * Extract root-ish core: for a.b.example.com -> example
 * This is not a full public suffix list implementation, but good enough for MVP.
 */
function extractRegistrableCore(hostname) {
  if (!hostname) return "";
  const h = hostname.toLowerCase().replace(/^\.+|\.+$/g, "");
  const parts = h.split(".").filter(Boolean);
  if (parts.length < 2) return parts[0] || "";

  // handle common 2nd-level TLD patterns very roughly
  const last = parts[parts.length - 1];
  const secondLast = parts[parts.length - 2];
  const thirdLast = parts[parts.length - 3];

  const secondLevelTlds = new Set(["co", "com", "org", "net", "ac", "gov"]);
  if (thirdLast && secondLevelTlds.has(secondLast) && last.length === 2) {
    // example.co.uk -> example
    return thirdLast;
  }
  return secondLast;
}

function extractDomainFromText(text) {
  if (!text) return "";
  const t = text.trim();

  // Try to catch "example.com" or "www.example.com"
  const m = t.match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i);
  if (m) return m[1].toLowerCase();

  // If looks like URL
  if (/^https?:\/\//i.test(t)) {
    const host = safeHostnameFromUrl_(t);
    return host ? host.toLowerCase() : "";
  }

  return "";
}

function safeHostnameFromUrl_(url) {
  try {
    // Apps Script supports URL in V8
    const u = new URL(url);
    return (u.hostname || "").toLowerCase();
  } catch (e) {
    // Sometimes href is relative or weird
    return "";
  }
}

function clampInt(n, lo, hi) {
  const x = Number.isFinite(n) ? n : 0;
  return Math.min(hi, Math.max(lo, x));
}

function getVerdict_(score) {
  if (score >= DEFAULTS.HIGH_RISK_THRESHOLD) return { label: "❌ HIGH RISK" };
  if (score >= DEFAULTS.SUSPICIOUS_THRESHOLD) return { label: "⚠️ SUSPICIOUS" };
  return { label: "✅ SAFE" };
}

function extractHeaderLine_(raw, headerName) {
  if (!raw) return "";
  const lines = raw.split(/\r?\n/);

  const target = headerName.toLowerCase() + ":";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line && line.toLowerCase().startsWith(target)) {
      // unfold continuation lines that start with whitespace
      let combined = line;
      let j = i + 1;
      while (j < lines.length && /^\s/.test(lines[j])) {
        combined += " " + lines[j].trim();
        j++;
      }
      return combined;
    }
  }
  return "";
}

function safeJsonParse_(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
}

function safeGetReplyTo_(message) {
  try {
    const raw = message.getRawContent() || "";
    const line = extractHeaderLine_(raw, "Reply-To");
    if (!line) return "";
    // "Reply-To: Name <x@y.com>" or "Reply-To: x@y.com"
    return line.replace(/^reply-to:\s*/i, "").trim();
  } catch (e) {
    return "";
  }
}

function escapeHtml_(s) {
  // CardService text generally supports basic markdown-ish, but keep safe.
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Levenshtein
function getLevenshteinDistance(s1, s2) {
  s1 = s1 || "";
  s2 = s2 || "";
  const m = s1.length, n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

// Optional: one-time auth helper (run manually from editor) 
function authorize() {
  UrlFetchApp.fetch("https://www.google.com");
}
