/**
 * Client for the real Rakshak API (apps/api), replacing mock-data.ts's
 * placeholder data. Mirrors static/index.html's existing authFetch() pattern
 * (prompt-once-and-exchange, Authorization: Bearer, retry once on 401) but
 * stores a real login session in localStorage rather than a raw API key in
 * sessionStorage -- a person, not a machine credential.
 */
import type { FullReport, InvestigationSummary, Severity, Source, ThreatSignal } from "@/lib/mock-data";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:10000";
const TOKEN_KEY = "rk_token";
const USER_KEY = "rk_user";

export class ApiError extends Error {}

export interface CurrentUser {
  id: string;
  email: string | null;
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function getCurrentUser(): CurrentUser | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CurrentUser;
  } catch {
    return null;
  }
}

function setSession(token: string, user: CurrentUser): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  window.dispatchEvent(new Event("rk-auth-changed"));
}

export function logout(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  window.dispatchEvent(new Event("rk-auth-changed"));
}

export function isLoggedIn(): boolean {
  return getToken() !== null;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(options.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(body.detail ?? body.message ?? `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

interface SessionResponse {
  token: string;
  expires_at: number;
  user: { id: string; email: string | null };
}

export async function register(email: string, password: string): Promise<void> {
  const session = await request<SessionResponse>("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  setSession(session.token, session.user);
}

export async function login(email: string, password: string): Promise<void> {
  const session = await request<SessionResponse>("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  setSession(session.token, session.user);
}

export async function forgotPassword(email: string): Promise<{ dev_reset_token?: string }> {
  return request("/api/v1/auth/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
}

export async function resetPassword(token: string, newPassword: string): Promise<void> {
  await request("/api/v1/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, new_password: newPassword }),
  });
}

// -- Threat intel --------------------------------------------------------

export interface ScamFeedEntry {
  url: string;
  host: string;
  threat: string;
  date_added: string;
}

export async function getScamFeed(): Promise<ScamFeedEntry[]> {
  const { entries } = await request<{ entries: ScamFeedEntry[] }>("/api/v1/threat-intel/feed");
  return entries;
}

// -- Investigations ----------------------------------------------------

/** The exact JSON `to_web()` produces (packages/reports/serializers), plus
 * the two columns list/detail responses attach from the owning `Investigation`
 * row. Backend field names kept verbatim (snake_case) rather than remapped. */
interface CanonicalReportJson {
  investigation_id: string;
  verdict: "scam" | "suspicious" | "likely_safe" | "unknown";
  risk_score: number;
  severity: "none" | "low" | "medium" | "high" | "critical";
  confidence: number;
  scam_type: string | null;
  explanation: string;
  red_flags: string[];
  extracted_entities: { kind: string; value: string; normalized_value: string | null; confidence: number; source: string }[];
  url_findings: unknown[];
  threat_intel: unknown[];
  recommended_actions: string[];
  model_metadata: { stage: string; provider: string | null; model_id: string | null; version: string | null; latency_ms: number | null }[];
  stage_status: { stage: string; state: string; error: string | null; duration_ms: number | null }[];
  generated_at: string;
  platform?: string;
  content_type?: string;
}

export async function analyzeText(text: string): Promise<CanonicalReportJson> {
  return request("/api/v1/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ platform: "web", content_type: "text", text }),
  });
}

export async function analyzeLink(url: string): Promise<CanonicalReportJson> {
  return request("/api/v1/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ platform: "web", content_type: "url", urls: [url] }),
  });
}

export async function analyzeUpload(file: File, text?: string): Promise<CanonicalReportJson> {
  const form = new FormData();
  form.append("file", file);
  if (text) form.append("text", text);
  return request("/api/v1/investigations/upload", { method: "POST", body: form });
}

export async function listInvestigations(limit = 50): Promise<InvestigationSummary[]> {
  const { investigations } = await request<{ investigations: CanonicalReportJson[] }>(
    `/api/v1/investigations?limit=${limit}`
  );
  return investigations.map(toSummary);
}

export async function getInvestigation(id: string): Promise<FullReport> {
  // analyze-form.tsx stashes the freshly-computed report here so the very
  // next page load (the common "just analyzed this" path) skips a
  // redundant round trip.
  if (typeof window !== "undefined") {
    const cached = sessionStorage.getItem(`rk_report:${id}`);
    if (cached) return toFullReport(JSON.parse(cached) as CanonicalReportJson);
  }
  const result = await request<{ status: string; report?: CanonicalReportJson }>(`/api/v1/investigations/${id}`);
  if (!result.report) throw new ApiError("Investigation still pending");
  return toFullReport(result.report);
}

// -- Mapping: backend CanonicalReport JSON -> existing UI shapes --------

const VERDICT_LABEL: Record<CanonicalReportJson["verdict"], string> = {
  scam: "Likely Scam",
  suspicious: "Suspicious",
  likely_safe: "Safe",
  unknown: "Unknown",
};

const SEVERITY_MAP: Record<CanonicalReportJson["severity"], Severity> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "SUSPICIOUS",
  low: "SUSPICIOUS",
  none: "SAFE",
};

const CONTENT_TYPE_LABEL: Record<string, InvestigationSummary["type"]> = {
  url: "Link",
  image: "Image",
  pdf: "Document",
  text: "Message",
  mixed: "Message",
  audio: "Message",
};

function toSummary(report: CanonicalReportJson): InvestigationSummary {
  return {
    id: report.investigation_id,
    source: (report.platform?.toUpperCase() as Source) ?? "WEB",
    type: CONTENT_TYPE_LABEL[report.content_type ?? "text"] ?? "Message",
    verdict: VERDICT_LABEL[report.verdict],
    risk: report.risk_score,
    severity: SEVERITY_MAP[report.severity],
    confidence: Math.round(report.confidence * 100),
    date: report.generated_at.slice(0, 10),
    status: "Closed",
  };
}

function toFullReport(report: CanonicalReportJson): FullReport {
  // The UI's threat-signal bars want at least two entries (a fixed WhatsApp/
  // Telegram preview block indexes signals[0]/[1] directly) -- red_flags is
  // the closest real signal the backend exposes per-item, so pad it out
  // rather than leaving a page that crashes on a clean/low-signal report.
  const signals: ThreatSignal[] =
    report.red_flags.length > 0
      ? report.red_flags.slice(0, 5).map((flag, i) => ({ label: flag, pct: Math.max(20, Math.round(report.confidence * 100) - i * 5) }))
      : [{ label: "No strong red flags detected", pct: Math.round(report.confidence * 100) }];
  while (signals.length < 2) signals.push({ label: "—", pct: 0 });

  return {
    id: report.investigation_id,
    verdict: VERDICT_LABEL[report.verdict],
    severity: SEVERITY_MAP[report.severity],
    confidence: Math.round(report.confidence * 100),
    score: report.risk_score,
    reason: report.explanation,
    signals,
    mlFindings: report.model_metadata.length
      ? report.model_metadata.map((m) => `${m.stage}: ${m.model_id ?? m.provider ?? "n/a"}`)
      : ["No ML signal recorded for this investigation"],
    cyberFindings: report.url_findings.length
      ? report.url_findings.map((f) => JSON.stringify(f))
      : ["No URL/domain findings for this investigation"],
    entities: report.extracted_entities.map((e) => e.value),
    domains: [],
    campaignId: (report.threat_intel[0] as { campaign_id?: string } | undefined)?.campaign_id ?? "",
    timeline: report.stage_status.map((s) => ({
      time: s.duration_ms != null ? `${s.duration_ms}ms` : "—",
      text: `${s.stage}: ${s.state}${s.error ? ` (${s.error})` : ""}`,
    })),
    actions: report.recommended_actions,
    aiExplanation: report.explanation,
  };
}
