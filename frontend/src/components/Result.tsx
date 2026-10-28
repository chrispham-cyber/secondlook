"use client";

import { useState } from "react";
import { SCAM_TYPE_LABEL, sendFeedback, VERDICT_LABEL, type FileCheck, type LinkReport, type ScanResult, type Verdict } from "@/lib/api";

// Four bands, four inks: green, yellow, orange, red.
export const TONE: Record<Verdict, "safe" | "caution" | "alert" | "danger"> = {
  likely_safe: "safe",
  suspicious: "caution",
  likely_scam: "alert",
  scam: "danger",
};

// Mirrors verdict_for() in backend/app/scoring.py.
const SCALE: { verdict: Verdict; range: string }[] = [
  { verdict: "likely_safe", range: "0–24" },
  { verdict: "suspicious", range: "25–59" },
  { verdict: "likely_scam", range: "60–84" },
  { verdict: "scam", range: "85–100" },
];

export function Scale({ current }: { current: Verdict }) {
  return (
    <ol className="scale" aria-label="How the score is read">
      {SCALE.map((s) => (
        <li key={s.verdict} data-tone={TONE[s.verdict]} aria-current={s.verdict === current ? "true" : undefined}>
          <span className="scale-word">{VERDICT_LABEL[s.verdict]}</span>
          <span className="scale-range">{s.range}</span>
        </li>
      ))}
    </ol>
  );
}

const SOURCE_LABEL = {
  ai: "Found by reading the message",
  link_check: "Found by checking the link",
  pattern: "Common scam wording",
  content_check: "Found by checking for hidden tricks",
  file_check: "Found by the file safety check",
} as const;

const FILE_STATUS = {
  clean: { tone: "safe", title: "No hidden code found in this file" },
  warning: { tone: "caution", title: "This file has some warning signs" },
  blocked: { tone: "danger", title: "We didn’t open this file" },
} as const;

function FileSafety({ check }: { check: FileCheck }) {
  const s = FILE_STATUS[check.status];
  const kind = check.file_type === "pdf" ? "PDF" : check.file_type === "docx" ? "Word document" : "file";
  return (
    <div className="block filecheck" data-tone={s.tone}>
      <h3>File safety check</h3>
      <p className="filecheck-title">{s.title}</p>
      {check.status === "blocked" ? (
        <p>
          It was stopped before anything read it, and it was never sent to the AI. The reasons are listed below under
          “Why we think so”.
        </p>
      ) : (
        <p>
          We looked inside this {kind} for programs, macros, and scripts before reading its text
          {check.pages ? ` (${check.pages} ${check.pages === 1 ? "page" : "pages"})` : ""}.
          {check.truncated ? " It was long, so we only read the first part." : ""}
        </p>
      )}
      <details>
        <summary>What we checked</summary>
        <ul>
          {check.checks_run.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <p className="hash">
          File fingerprint (SHA-256): <code>{check.sha256}</code>
        </p>
      </details>
    </div>
  );
}

function ageText(days: number | null) {
  if (days === null) return null;
  if (days < 1) return "Website created today";
  if (days < 60) return `Website created ${days} day${days === 1 ? "" : "s"} ago`;
  if (days < 730) return `Website about ${Math.round(days / 30)} months old`;
  return `Website about ${Math.round(days / 365)} years old`;
}

export function isInternational(link: LinkReport): boolean {
  return !!link.host_ascii && !!link.host_unicode && link.host_ascii !== link.host_unicode;
}

/** The name to print for a link. A disguised address renders like the real one, so use its real form. */
export function addressName(link: LinkReport): string {
  return isInternational(link) ? link.host_ascii! : link.registrable_domain || link.host;
}

/** For international addresses: how it appears in messages, what it imitates, and the alphabets used. */
export function RealAddress({ link }: { link: LinkReport }) {
  if (!isInternational(link)) return null;
  return (
    <div className="real-address">
      <p>
        Appears in messages as <code>{link.host_unicode}</code>
        {link.looks_like ? (
          <>
            , made to look like <strong>{link.looks_like}</strong>. It is not.
          </>
        ) : (
          "."
        )}
      </p>
      {link.scripts && link.scripts.length > 0 && <p>Alphabets in the address: {link.scripts.join(", ")}</p>}
    </div>
  );
}

export function Result({ result }: { result: ScanResult }) {
  const tone = TONE[result.verdict];
  const scamType = result.scam_type !== "none" ? SCAM_TYPE_LABEL[result.scam_type] ?? null : null;
  // A low score is not a clean bill of health when something odd was still found.
  const oddities = result.verdict === "likely_safe" && result.red_flags.some((f) => f.severity !== "low");

  return (
    <section className="result" aria-labelledby="verdict-heading">
      <div className="verdict" data-tone={tone}>
        <div className="stamp" aria-hidden="true">
          <span className="pct">{result.risk_score}%</span>
          <span className="word">{VERDICT_LABEL[result.verdict]}</span>
          <span className="sub">scam risk</span>
        </div>
        <div>
          <h2 id="verdict-heading">
            <span className="sr-only">
              {VERDICT_LABEL[result.verdict]}, {result.risk_score} percent scam risk.{" "}
            </span>
            {result.headline}
          </h2>
          {scamType && <p className="scam-type">Looks like: {scamType}</p>}
        </div>
      </div>

      <Scale current={result.verdict} />

      {oddities && (
        <p className="degraded" role="note">
          Low risk doesn’t mean safe. We still found something unusual, listed under “Why we think so”. If it asks for
          money, a code, or a login, check with the sender another way first.
        </p>
      )}

      {result.meta.degraded && (
        <p className="degraded" role="note">
          The AI reader was unavailable, so this check used link and wording rules only. It may miss scams that a closer read
          would catch.
        </p>
      )}

      {result.file_check && <FileSafety check={result.file_check} />}

      {result.what_to_do.length > 0 && (
        <div className="block">
          <h3>What to do</h3>
          <ol className="steps">
            {result.what_to_do.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
        </div>
      )}

      {(result.red_flags.length > 0 || result.safe_signals.length > 0) && (
        <div className="block">
          <h3>Why we think so</h3>
          <ul className="flags">
            {result.red_flags.map((f, i) => (
              <li key={`r${i}`}>
                <span className="dot" data-sev={f.severity} aria-hidden="true" />
                <div>
                  <strong>
                    <span className="sr-only">{f.severity} warning: </span>
                    {f.title}
                  </strong>
                  {f.detail && <p>{f.detail}</p>}
                  <div className="source">{SOURCE_LABEL[f.source]}</div>
                </div>
              </li>
            ))}
            {result.safe_signals.map((s, i) => (
              <li key={`s${i}`}>
                <span className="dot ok" aria-hidden="true" />
                <div>
                  <strong>
                    <span className="sr-only">Reassuring sign: </span>
                    {s}
                  </strong>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.links.length > 0 && (
        <div className="block">
          <h3>Links in the message</h3>
          <div className="links">
            {result.links.map((l) => {
              const age = ageText(l.domain_age_days);
              return (
                <div className="link-row" key={l.url}>
                  <div className="domain">{addressName(l)}</div>
                  <div className="full">{l.url}</div>
                  <RealAddress link={l} />
                  <ul>
                    {l.official_brand && <li>This is an official {l.official_brand} website.</li>}
                    {l.on_blocklist && <li>Listed on a public list of known phishing sites.</li>}
                    {age && <li>{age}</li>}
                    {l.checks
                      .filter((c) => c.name !== "blocklist")
                      .map((c) => (
                        <li key={c.name}>{c.detail}</li>
                      ))}
                    {!l.official_brand && !l.on_blocklist && !age && l.checks.length === 0 && (
                      <li>No problems found with this address, but that alone doesn’t make it safe.</li>
                    )}
                  </ul>
                </div>
              );
            })}
          </div>
          <p className="hint">Don’t open these links to check them. We looked them up without visiting them.</p>
        </div>
      )}

      <details className="read">
        <summary>What we read and how we scored it</summary>
        {result.extracted_text && <pre>{result.extracted_text}</pre>}
        <dl>
          {result.claimed_sender && (
            <>
              <dt>Claims to be from</dt>
              <dd>{result.claimed_sender}</dd>
            </>
          )}
          <dt>AI estimate</dt>
          <dd>{result.score_breakdown.ai_score === null ? "Not available" : `${result.score_breakdown.ai_score}%`}</dd>
          {result.score_breakdown.text_model_score != null && (
            <>
              <dt>Pattern model estimate</dt>
              <dd>{result.score_breakdown.text_model_score}% (trained on thousands of real texts)</dd>
            </>
          )}
          {result.score_breakdown.adjustments.map((a, i) => (
            <div key={i} style={{ display: "contents" }}>
              <dt>Raised to {a.min_score}%</dt>
              <dd>{a.reason}</dd>
            </div>
          ))}
          <dt>Checked in</dt>
          <dd>{(result.meta.latency_ms / 1000).toFixed(1)} seconds</dd>
        </dl>
      </details>

      <Feedback scanId={result.id} />
    </section>
  );
}

function Feedback({ scanId }: { scanId: string }) {
  const [state, setState] = useState<"idle" | "sent" | "error">("idle");

  async function send(correct: boolean) {
    try {
      await sendFeedback(scanId, correct);
      setState("sent");
    } catch {
      setState("error");
    }
  }

  if (state === "sent") {
    return (
      <p className="feedback" role="status">
        Thanks. Your answer helps us measure how often the checker is right.
      </p>
    );
  }
  return (
    <div className="feedback">
      <p id="fb-q">Was this answer right?</p>
      <button type="button" className="btn secondary" aria-describedby="fb-q" onClick={() => send(true)}>
        Yes
      </button>
      <button type="button" className="btn secondary" aria-describedby="fb-q" onClick={() => send(false)}>
        No
      </button>
      {state === "error" && <span className="hint">Couldn’t send that. Try again.</span>}
    </div>
  );
}
