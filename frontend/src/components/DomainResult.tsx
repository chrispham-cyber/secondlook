"use client";

import { VERDICT_LABEL, type DomainCheck } from "@/lib/api";
import { addressName, RealAddress, Scale, TONE } from "./Result";

export function DomainResult({ result }: { result: DomainCheck }) {
  const link = result.link;
  return (
    <section className="result" aria-labelledby="domain-heading">
      <div className="verdict" data-tone={TONE[result.verdict]}>
        <div className="stamp" aria-hidden="true">
          <span className="pct">{result.risk_score}%</span>
          <span className="word">{VERDICT_LABEL[result.verdict]}</span>
          <span className="sub">scam risk</span>
        </div>
        <div>
          <h2 id="domain-heading">
            <span className="sr-only">
              {VERDICT_LABEL[result.verdict]}, {result.risk_score} percent scam risk.{" "}
            </span>
            {result.headline}
          </h2>
        </div>
      </div>

      <Scale current={result.verdict} />

      <div className="block">
        <h3>What to do</h3>
        <ol className="steps">
          {result.what_to_do.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      </div>

      <div className="block">
        <h3>What we found</h3>
        <div className="links">
          <div className="link-row">
            <div className="domain">{addressName(link)}</div>
            <RealAddress link={link} />
            <ul>
              {link.checks
                .filter((c) => c.name !== "blocklist")
                .map((c) => (
                  <li key={c.name}>{c.detail}</li>
                ))}
              {result.facts.map((f, i) => (
                <li key={`f${i}`}>{f}</li>
              ))}
            </ul>
          </div>
        </div>
        {!result.network_checked && (
          <p className="hint">Website age and phishing lists weren’t checked because network checks are turned off.</p>
        )}
        <p className="hint">We looked this address up without visiting it.</p>
      </div>
    </section>
  );
}
