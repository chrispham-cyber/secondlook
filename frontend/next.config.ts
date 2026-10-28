import type { NextConfig } from "next";

// The browser only talks to this Next.js app; /api/* is proxied to the FastAPI backend.
// Rewrites are resolved at build time, so set BACKEND_URL before `next build`.
const backend = process.env.BACKEND_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  output: "standalone",
  experimental: {
    // A scan can take over 30s (the default) with a local model or several link lookups.
    proxyTimeout: 200_000,
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default nextConfig;
