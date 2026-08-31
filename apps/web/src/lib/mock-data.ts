/**
 * Placeholder data for the Rakshak web UI, ported verbatim from the
 * claude.ai/design mockup (project 82bc2623, Rakshak.dc.html). The frontend
 * has zero business logic (task.md rule #1) — this file is scaffolding until
 * phase 16 wires real API calls against the FastAPI backend.
 */

export type Severity = "CRITICAL" | "HIGH" | "SUSPICIOUS" | "SAFE";
export type Source = "WEB" | "WHATSAPP" | "TELEGRAM";

export interface InvestigationSummary {
  id: string;
  source: Source;
  type: "Link" | "Message" | "Image" | "Document";
  verdict: string;
  risk: number;
  severity: Severity;
  confidence: number;
  date: string;
  status: string;
}

export const investigations: InvestigationSummary[] = [
  { id: "RX-10291", source: "WEB", type: "Link", verdict: "Likely Scam", risk: 87, severity: "HIGH", confidence: 94, date: "2026-08-07", status: "Closed" },
  { id: "RX-10288", source: "WHATSAPP", type: "Message", verdict: "Likely Scam", risk: 91, severity: "CRITICAL", confidence: 97, date: "2026-08-06", status: "Closed" },
  { id: "RX-10281", source: "WEB", type: "Image", verdict: "Suspicious", risk: 54, severity: "SUSPICIOUS", confidence: 81, date: "2026-08-05", status: "Closed" },
  { id: "RX-10277", source: "TELEGRAM", type: "Link", verdict: "Safe", risk: 12, severity: "SAFE", confidence: 88, date: "2026-08-04", status: "Closed" },
  { id: "RX-10265", source: "WEB", type: "Document", verdict: "Likely Scam", risk: 79, severity: "HIGH", confidence: 90, date: "2026-08-02", status: "Closed" },
  { id: "RX-10259", source: "WHATSAPP", type: "Message", verdict: "Suspicious", risk: 48, severity: "SUSPICIOUS", confidence: 76, date: "2026-07-30", status: "Closed" },
];

export interface Campaign {
  id: string;
  name: string;
  confidence: number;
  investigations: number;
  indicators: number;
  domains: number;
  phones: number;
  desc: string;
  pattern: string;
}

export const campaigns: Campaign[] = [
  { id: "CMP-014", name: "Digital Arrest Scam", confidence: 91, investigations: 42, indicators: 17, domains: 8, phones: 12, desc: "Impersonation of law enforcement demanding payment over video call to avoid a fabricated arrest.", pattern: 'Cold call claiming a parcel/courier issue, escalates to a fake police video call, demands urgent payment via UPI to "resolve" a legal case.' },
  { id: "CMP-011", name: "Fake Courier Delivery Fee", confidence: 83, investigations: 29, indicators: 11, domains: 14, phones: 6, desc: "SMS or WhatsApp lure requesting a small customs or delivery fee to release a parcel.", pattern: "Shortened link to a spoofed courier page requesting card details for a nominal fee." },
  { id: "CMP-009", name: "Loan App Harassment", confidence: 76, investigations: 18, indicators: 9, domains: 5, phones: 21, desc: "Predatory lending apps harvest contacts on install, then extort borrowers with threats.", pattern: "App requests excessive permissions, disburses a small loan, then demands repayment at extreme interest under threat of exposing contacts." },
];

export interface Entity {
  value: string;
  type: "Domain" | "Phone" | "UPI ID" | "Email";
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  related: number;
}

export const entities: Entity[] = [
  { value: "secure-parcel-track.com", type: "Domain", confidence: 96, firstSeen: "2026-06-02", lastSeen: "2026-08-07", related: 14 },
  { value: "+91 88••• •••17", type: "Phone", confidence: 89, firstSeen: "2026-05-20", lastSeen: "2026-08-06", related: 9 },
  { value: "scamvictim@pay.upi", type: "UPI ID", confidence: 92, firstSeen: "2026-07-01", lastSeen: "2026-08-05", related: 6 },
  { value: "support@courier-refund.net", type: "Email", confidence: 85, firstSeen: "2026-04-18", lastSeen: "2026-07-30", related: 11 },
  { value: "digitalarrest-verify.in", type: "Domain", confidence: 98, firstSeen: "2026-03-11", lastSeen: "2026-08-07", related: 42 },
];

export const investigationStages = [
  "Receiving content",
  "Understanding content",
  "Extracting entities",
  "ML analysis",
  "Cybersecurity checks",
  "Threat intelligence",
  "Risk fusion",
  "AI reasoning",
  "Report ready",
];

export interface ThreatSignal {
  label: string;
  pct: number;
}

const reportSignals: ThreatSignal[] = [
  { label: "Urgency language", pct: 88 },
  { label: "Impersonation of authority", pct: 74 },
  { label: "Suspicious URL structure", pct: 91 },
  { label: "Credential harvesting pattern", pct: 69 },
  { label: "Known campaign similarity", pct: 82 },
];

export interface FullReport {
  id: string;
  verdict: string;
  severity: Severity;
  confidence: number;
  score: number;
  reason: string;
  signals: ThreatSignal[];
  mlFindings: string[];
  cyberFindings: string[];
  entities: string[];
  domains: { domain: string; registered: string; reputation: string; campaign: string }[];
  campaignId: string;
  timeline: { time: string; text: string }[];
  actions: string[];
  aiExplanation: string;
}

export function getReport(id: string): FullReport {
  const raw = investigations.find((i) => i.id === id) ?? investigations[0];
  return {
    id: raw.id,
    verdict: raw.verdict,
    severity: raw.severity,
    confidence: raw.confidence,
    score: raw.risk,
    reason: "This content combines urgency language, impersonation of an official authority, and a link to a domain registered nine days ago with no prior reputation history.",
    signals: reportSignals,
    mlFindings: [
      "Text classifier: 93% match to known scam phrasing patterns",
      "Image OCR: no manipulation detected in attached screenshot",
      "Sentiment model: high urgency, fear-based pressure detected",
    ],
    cyberFindings: [
      "Domain registered 9 days ago via privacy-shielded registrar",
      "TLS certificate issued same day as registration",
      "Redirect chain terminates on a credential-harvesting form",
    ],
    entities: ["secure-parcel-track.com", "+91 88••• •••17", "scamvictim@pay.upi", "Reference #INV-33210"],
    domains: [
      { domain: "secure-parcel-track.com", registered: "9 days ago", reputation: "Poor", campaign: "Fake Courier Delivery Fee" },
      { domain: "digitalarrest-verify.in", registered: "5 months ago", reputation: "Malicious", campaign: "Digital Arrest Scam" },
    ],
    campaignId: "CMP-014",
    timeline: [
      { time: "00:00", text: "Content received from Web" },
      { time: "00:02", text: "Entities extracted: 1 domain, 1 phone number" },
      { time: "00:04", text: "ML classifier flagged high scam probability" },
      { time: "00:06", text: "Domain checked against threat intelligence feeds" },
      { time: "00:08", text: "Matched to Digital Arrest Scam campaign" },
      { time: "00:10", text: "Risk fused, report generated" },
    ],
    actions: [
      "Do not click the link or share payment details",
      "Block and report the sender",
      "If payment was made, contact your bank immediately",
    ],
    aiExplanation: "Rakshak combined language pattern analysis, domain age and reputation, and similarity to a known campaign to reach this verdict. The short domain age and urgency language are the strongest contributing factors.",
  };
}

export const analyzeChecklist: Record<string, string[]> = {
  message: ["Urgency & pressure language", "Impersonation of a person or brand", "Embedded links & phone numbers", "Similarity to known scam scripts"],
  image: ["OCR text extraction", "Logo & brand impersonation", "Manipulation / tampering signs", "Embedded links & QR codes"],
  link: ["Domain age & registration", "TLS certificate history", "Redirect chain analysis", "Known campaign matching"],
  document: ["Metadata & authoring history", "Embedded links & macros", "Letterhead / logo impersonation", "Known campaign matching"],
};
