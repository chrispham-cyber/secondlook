import type { Metadata, Viewport } from "next";
import Link from "next/link";
import { Atkinson_Hyperlegible_Next } from "next/font/google";
import "./globals.css";

// Designed by the Braille Institute for low-vision readers: fits an audience that skews older.
const atkinson = Atkinson_Hyperlegible_Next({
  variable: "--font-body",
  subsets: ["latin"],
  weight: ["400", "600", "800"],
});

export const metadata: Metadata = {
  title: "Second Look — is this message a scam?",
  description:
    "Upload a screenshot of a text, email, or website and get a plain-language answer: scam or not, why, and what to do next.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#eef2f6" },
    { media: "(prefers-color-scheme: dark)", color: "#0f1a2e" },
  ],
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={atkinson.variable} suppressHydrationWarning>
      <body>
        <a className="skip" href="#main">
          Skip to the checker
        </a>
        <header className="site-header">
          <Link href="/" className="wordmark" aria-label="Second Look home">
            <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true">
              <circle cx="13" cy="13" r="9" fill="none" stroke="currentColor" strokeWidth="3" />
              <path d="M20 20l8 8" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" />
              <path d="M9 13.5l3 3 5-6" fill="none" stroke="var(--safe)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Second Look
          </Link>
          <nav aria-label="Main">
            <Link href="/#how">How it works</Link>
            <Link href="/stats">Stats</Link>
          </nav>
        </header>
        <main id="main">{children}</main>
        <footer className="site-footer">
          <p>
            Second Look can make mistakes. When money or personal information is involved, contact the company using a phone
            number or app you already trust.
          </p>
          <p>
            Lost money to a scam? Call your bank first, then report it at{" "}
            <a href="https://reportfraud.ftc.gov" target="_blank" rel="noreferrer">
              reportfraud.ftc.gov
            </a>
            .
          </p>
        </footer>
      </body>
    </html>
  );
}
