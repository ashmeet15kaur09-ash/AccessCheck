# AccessCheck

AccessCheck audits public websites with Playwright and axe-core, and stores scan findings in SQLite.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the FastAPI scan API on its managed `/api` service
- `pnpm --filter @workspace/accesscheck run dev` — run the AccessCheck React/Vite frontend
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `cd artifacts/api-server && python -m pytest` — run API and URL-security tests
- `uv sync && uv run playwright install chromium` — install Python dependencies and the scan browser
- Optional env: `ACCESSCHECK_DB_PATH` — override the default SQLite history file

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React, TypeScript, Tailwind CSS, Wouter, React Query
- API: Python FastAPI
- Scanning: Playwright Python, Chromium, axe-core
- DB: SQLite
- API codegen: Orval (from OpenAPI spec)
- Frontend build: Vite

## Where things live

- `artifacts/accesscheck/` — frontend
- `artifacts/api-server/accesscheck/` — FastAPI API, scanner, SSRF guards, and SQLite persistence
- `artifacts/api-server/tests/` — backend and security tests
- `lib/api-spec/openapi.yaml` — API contract source

## Architecture decisions

- Scan history uses SQLite because the product brief explicitly requested it.
- Scan URLs are restricted to public HTTP(S) destinations; browser requests re-check DNS and redirects before requesting them.
- Scan findings are automated axe-core results, not a WCAG compliance score or certification.

## Product

Users can run automated audits, inspect axe findings and evidence, filter and compare saved scans, export CSV, and print a report.

## User preferences

- Keep real scan data separate from demo data; do not invent accessibility scores or claim automated checks establish compliance.
- Use free and open-source tools; do not require paid AI services.

## Gotchas

- Chromium must be installed with Playwright before the first real scan.
- SQLite data is local to the service filesystem; configure durable storage before moving to a host with ephemeral filesystems.
- Browser request interception and DNS rechecks reduce SSRF risk but are not a replacement for an OS/network-isolated browser in high-risk multi-tenant deployments.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
