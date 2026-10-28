"use client";

import { useEffect, useState } from "react";
import { getStats, SCAM_TYPE_LABEL, VERDICT_LABEL, type Stats, type Verdict } from "@/lib/api";

const ORDER: Verdict[] = ["scam", "likely_scam", "suspicious", "likely_safe"];

export function StatsView() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch(() => setError(true));
  }, []);

  if (error) return <p className="error">Couldn’t load stats. Make sure the backend is running, then refresh.</p>;
  if (!stats) return <p className="hint">Loading…</p>;
  if (stats.total_scans === 0) return <p className="hint">No checks yet. Run one from the home page and come back.</p>;

  const max = Math.max(1, ...Object.values(stats.by_verdict));
  const pct = (x: number | null) => (x === null ? "—" : `${Math.round(x * 100)}%`);

  return (
    <>
      <dl className="stat-list">
        <div>
          <dt>Messages checked</dt>
          <dd>{stats.total_scans}</dd>
        </div>
        <div>
          <dt>People said we were right</dt>
          <dd>{pct(stats.feedback_agreement)}</dd>
        </div>
        <div>
          <dt>Average time</dt>
          <dd>{stats.avg_latency_ms === null ? "—" : `${(stats.avg_latency_ms / 1000).toFixed(1)}s`}</dd>
        </div>
        <div>
          <dt>Average AI cost</dt>
          <dd>{stats.avg_cost_usd === null ? "—" : `${(stats.avg_cost_usd * 100).toFixed(1)}¢`}</dd>
        </div>
      </dl>

      <div className="block">
        <h3>Verdicts</h3>
        <div className="bars">
          {ORDER.map((v) => {
            const n = stats.by_verdict[v] ?? 0;
            return (
              <div className="bar-row" key={v}>
                <span>{VERDICT_LABEL[v]}</span>
                <div className="bar-track" aria-hidden="true">
                  <div className="bar-fill" style={{ width: `${(n / max) * 100}%` }} />
                </div>
                <span className="n">{n}</span>
              </div>
            );
          })}
        </div>
      </div>

      {stats.top_scam_types.length > 0 && (
        <div className="block">
          <h3>Most common scam types</h3>
          <ul className="flags">
            {stats.top_scam_types.map(([type, n]) => (
              <li key={type}>
                <span className="dot" data-sev="high" aria-hidden="true" />
                <div>
                  <strong>{SCAM_TYPE_LABEL[type] ?? type}</strong>
                  <p>{n} checks</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}
