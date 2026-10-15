# AccessCheck — Website Accessibility Auditor

AccessCheck runs real, automated accessibility checks against public websites using Chromium, Playwright, and the local axe-core engine. It saves scan history to SQLite and presents rule-level findings with affected markup, evidence, WCAG references, and axe remediation guidance.

Automated results are not a compliance certification. Keyboard, screen-reader, cognitive, and other manual checks are still necessary.

## Run on Replit

The project workflows start the React/Vite website and the FastAPI service. Scan history is stored in `artifacts/api-server/data/accesscheck.sqlite3`.

Python dependencies are tracked in `pyproject.toml` and `uv.lock`; browser binaries are provisioned for the workspace with:

```sh
uv sync
uv run playwright install chromium
```

The API is mounted at `/api`. The React app calls it through same-origin routes. No paid API keys or sample scan data are used.

## Architecture

- **Frontend:** React, TypeScript, Tailwind CSS, Wouter, React Query, Recharts, and generated OpenAPI hooks (`artifacts/accesscheck`).
- **API:** FastAPI (`artifacts/api-server/accesscheck`), served by the existing `/api` service.
- **Browser and audit engine:** Playwright Python with Chromium and the pinned local `axe-core` package.
- **Persistence:** SQLite. Set `ACCESSCHECK_DB_PATH` to choose a different file path.
- **OpenAPI:** `lib/api-spec/openapi.yaml` is the source of truth for generated client hooks and schemas.

## Security and resource limits

- Only `http`/`https` URLs on their standard ports are accepted; embedded credentials, local names, and non-public IP ranges are rejected.
- DNS is resolved and checked before navigation and again for each browser request. Redirects and embedded requests are subject to the same checks.
- Browser downloads and service workers are disabled. Each scan has a time limit, at most two scans run concurrently, and the browser request count and response sizes are capped.
- Query strings and fragments are removed from stored and displayed scan URLs. The CSV export escapes formula-leading cells.
- Scan identifiers are validated before they are used in parameterized SQLite queries. Website-provided text is returned as data and rendered as text by the frontend.

These controls reduce SSRF and resource-exhaustion risks; they are not a substitute for a separately sandboxed browser service in a high-risk, multi-tenant deployment.

## API

- `GET /api/healthz` — service health
- `GET /api/dashboard` — totals derived from completed saved scans
- `GET /api/scans?limit=50` — recent scan history
- `POST /api/scans` — run an automated scan (`{"url":"https://example.com"}`)
- `GET /api/scans/{scanId}` — findings and evidence for a saved scan
- `GET /api/scans/{scanId}/export.csv` — CSV export

## Tests

Run the Python test suite:

```sh
cd artifacts/api-server
python -m pytest
```

Tests cover URL rejection, empty results, invalid IDs and local-file access attempts, scan failures/timeouts, safe database errors, and CSV formula injection. The scanner tests use controlled engine responses; they do not replace a live scan against a public site.

The generated TypeScript API client can be refreshed after OpenAPI changes with:

```sh
pnpm --filter @workspace/api-spec run codegen
```

## GitHub and deployment

Commit and push the project (including `pyproject.toml`, `uv.lock`, and `artifacts/api-server/requirements.txt`) to a GitHub repository. Do not commit the SQLite database or browser cache. Replit Publish uses the configured web and API services; the API build installs the Python dependencies and Chromium before starting FastAPI. For other hosts, install `requirements.txt`, install the matching Playwright Chromium browser, provide a writable persistent path through `ACCESSCHECK_DB_PATH`, and run Uvicorn behind an HTTPS reverse proxy. Ensure that host also enforces outbound network restrictions for the browser process.
