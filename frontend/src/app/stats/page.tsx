import type { Metadata } from "next";
import { StatsView } from "@/components/StatsView";

export const metadata: Metadata = { title: "Stats — Second Look" };

export default function StatsPage() {
  return (
    <section className="intro">
      <h1 className="page-title">What people are checking</h1>
      <p>Totals from every check on this server. We keep the verdict and scam type, never the screenshot or message.</p>
      <StatsView />
    </section>
  );
}
