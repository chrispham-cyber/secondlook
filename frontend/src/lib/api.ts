// Mirrors backend/app/schemas.py

export type Severity = "low" | "medium" | "high";
export type Verdict = "likely_safe" | "suspicious" | "likely_scam" | "scam";

export interface RedFlag {
  title: string;
  detail: string;
  severity: Severity;
  source: "ai" | "link_check" | "pattern";
}

export interface LinkReport {
  url: string;
  host: string;
  registrable_domain: string;
  official_brand: string | null;
  domain_age_days: number | null;
  on_blocklist: boolean;
  checks: { name: string; detail: string; severity: Severity }[];
}

export interface ScanResult {
  id: string;
  risk_score: number;
  verdict: Verdict;
  headline: string;
  scam_type: string;
  channel: string;
  claimed_sender: string;
  red_flags: RedFlag[];
  safe_signals: string[];
  what_to_do: string[];
  links: LinkReport[];
  extracted_text: string;
  score_breakdown: { ai_score: number | null; text_model_score?: number | null; adjustments: { reason: string; min_score: number }[] };
  meta: {
    model: string | null;
    latency_ms: number;
    cost_usd: number;
    input_tokens: number;
    output_tokens: number;
    degraded: boolean;
    degraded_reason: string | null;
  };
}

export interface Stats {
  total_scans: number;
  by_verdict: Record<string, number>;
  top_scam_types: [string, number][];
  avg_latency_ms: number | null;
  avg_cost_usd: number | null;
  feedback_count: number;
  feedback_agreement: number | null;
  degraded_scans: number;
}

export class ApiError extends Error {}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
  } catch {
    /* not JSON */
  }
  if (res.status === 413) return "That file is too large. Try a smaller screenshot.";
  if (res.status >= 500) return "The checker is having trouble right now. Please try again in a minute.";
  return "Something went wrong. Please try again.";
}

export async function scanMessage(input: { image?: File | null; text?: string }): Promise<ScanResult> {
  const form = new FormData();
  if (input.image) form.append("image", input.image);
  if (input.text?.trim()) form.append("text", input.text.trim());
  let res: Response;
  try {
    res = await fetch("/api/scan", { method: "POST", body: form });
  } catch {
    throw new ApiError("Couldn't reach the checker. Check your internet connection and try again.");
  }
  if (!res.ok) throw new ApiError(await errorMessage(res));
  return res.json();
}

export async function sendFeedback(scanId: string, correct: boolean): Promise<void> {
  const res = await fetch(`/api/scans/${scanId}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ correct }),
  });
  if (!res.ok) throw new ApiError(await errorMessage(res));
}

export async function getStats(): Promise<Stats> {
  const res = await fetch("/api/stats", { cache: "no-store" });
  if (!res.ok) throw new ApiError(await errorMessage(res));
  return res.json();
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  likely_safe: "Looks safe",
  suspicious: "Be careful",
  likely_scam: "Likely scam",
  scam: "Scam",
};

export const SCAM_TYPE_LABEL: Record<string, string> = {
  none: "No scam detected",
  toll_or_parking_payment: "Fake toll or parking bill",
  package_delivery: "Fake delivery notice",
  bank_or_payment_app: "Bank or payment-app impersonation",
  account_login_phishing: "Fake login or account warning",
  government_impersonation: "Government impersonation",
  tech_support: "Fake tech support",
  family_emergency: "Family emergency scam",
  romance: "Romance scam",
  investment_or_crypto: "Investment or crypto scam",
  job_or_task: "Fake job offer",
  prize_or_lottery: "Fake prize or lottery",
  marketplace_or_overpayment: "Marketplace scam",
  subscription_or_invoice: "Fake invoice or renewal",
  utility_shutoff: "Fake utility shutoff",
  wrong_number_opener: "“Wrong number” opener",
  other: "Other scam",
};
