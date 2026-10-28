# Second Look: frontend

Next.js app for uploading a screenshot or pasting a message and reading the result. It proxies `/api/*` to the FastAPI backend at `BACKEND_URL` (default `http://localhost:8000`).

```bash
npm install
npm run dev        # http://localhost:3000, backend must be running
npm run lint && npx tsc --noEmit
npm run build
```

See the [main README](../README.md) for setup, architecture, and evals.
