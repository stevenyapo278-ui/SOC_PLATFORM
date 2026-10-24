# AGENTS.md

## Project

SOC Sentinel — read-only Express 4 console over the SentinelOne Management API (`/web/api/v2.1`), AD/LDAP login, static Boron-theme frontend. CommonJS only (`require`, `'use strict'`). Node >= 20. UI strings, log messages, and API errors are **French** — keep them French.

## Commands

```bash
npm test          # node --test tests/*.test.js — no other runner, no lint/typecheck
npm start         # node server.js
npm run dev       # node --watch server.js
npm run docs:build  # regenerate public/api-docs-data/ from formatted_swagger_2_1.json
docker compose up -d   # local PostgreSQL + pgvector (port 5435, DB "soc", user "soc")
```

Single test file: `node --test tests/api.test.js`. There is no ESLint/Prettier/tsc config. `tests/store.test.js` additionally needs a PostgreSQL (it creates `soc_test`, or `TEST_DATABASE_URL`); it **skips itself** when no server answers, so `npm test` stays green anywhere.

## Architecture

- `server.js` → `src/config.js` (env, evaluated **at require time**) → `src/app.js` `createApp()`
- Routes: `src/routes/auth.routes.js` (`/api/auth/*`), `src/routes/sentinel.routes.js` (`/api/overview|agents|threats|alerts|activities|health`)
- S1 client: `src/sentinelone/client.js` — undici `fetch`, in-memory TTL cache, optional `tlsInsecure` dispatcher. **Processes/applications are queried as lists: `GET /agents/{processes|applications}?ids=<agentId>`** (the `/agents/{id}/…` path returns 404 on real consoles); `listAgentApplications` retries `application-management/inventory/applications` on 404/403.
- Normalizers: `src/sentinelone/normalize.js` — **must accept both nested (`threatInfo`/`alertInfo`) and flat S1 shapes**
- Overview: `src/sentinelone/overview.js` + `/api/overview` uses `Promise.allSettled`; partial S1 failures become `warnings[]`, only all-4-failed is an error. When the DB is active, KPIs come from SQL aggregates (`store.overviewCounts()`) instead of a sample → exact totals and `sampled.* = false`; the sample is still used for the « récents » lists and as fallback.
- PostgreSQL (optional): `src/db/index.js` (pool, migrations from `src/db/migrations/*.sql`, `migrateOnce()` de-duplicates concurrent runs), enabled only when `DATABASE_URL` set. Schema: threats/alerts/threat_notes/activities/agents + `sync_cursors` + `embeddings` (pgvector, dim `EMBEDDINGS_DIM` default 1536, HNSW). Text builder for RAG: `src/services/embeddings.js` (`buildEmbeddingContent`). Local DB: `docker compose up -d` (pgvector/pg16, port **5435** — 5432 taken).
- Synchro S1→PG (`src/services/sync.js`, scheduler started by `server.js` after `migrate()`): **incremental by default**. Watermarks live in `sync_cursors`; each run sends `updatedAt__gte`/`reportedAt__gte`/`createdAt__gte` (minus `DB_SYNC_OVERLAP_MIN`, default 15 min) except in **full** mode — used for the first run and for the hourly reconciliation (`DB_SYNC_RECONCILE_MIN`, default 60 min) that catches edits on old objects. Upserts are idempotent (`runSync` / `syncNow`, single-flight + `DB_SYNC_REFRESH_MIN_MS` anti-burst). Cursors only advance after a fully successful run. **Window = `DB_SYNC_PAGE_SIZE` × `DB_SYNC_MAX_PAGES` (500 × 10 = 5 000 objects/entity/run) and must exceed the fleet (~1 400 endpoints)** — beyond it the run logs `status: partial` + `fenêtre … tronquée`.
- Views read **from PostgreSQL**: `src/db/store.js` implements the same `{data, pagination}` contract as the S1 client (returns the stored `raw` JSONB, so normalizers are untouched) with offset cursors. Per-request limit is **100**; internal KPI reads pass `maxLimit` (up to 5 000) via `paged()`. `src/routes/sentinel.routes.js` builds a reader with `createReader(client)` = `Object.create(client)` overriding the list methods; `?refresh=1` runs a delta sync first, and any SQL/sync failure falls back to the live S1 client (`log.warn`). Live endpoints that are not synced (processes, applications, timeline, `/api/health`, `/settings`) keep using `client` directly.
- AI / RAG / chat / voix (all optional, need `DATABASE_URL` + a provider in BDD):
  - Migrations `001_init.sql` (SOC + `embeddings`) and `002_ai.sql` (ai_providers/ai_keys/ai_models/ai_usage_log/conversations/chat_messages).
  - Providers are **driven from the DB, never from env keys** — admin CRUD in `src/routes/ai.routes.js` (`/api/ai/*`, keys always masked `abcd…wxyz` on read). Fallback chain + circuit breakers: `src/ai/providers.js`, `src/ai/circuitBreaker.js`, usage/budget: `src/ai/usageTracker.js`.
  - Embeddings: `src/ai/embeddings.js` (DB `EMBEDDING` models, dim check), indexing: `src/services/ragIndex.js` (runs 500 ms after each sync when `AI_RAG_INDEX_ENABLED`), search: `src/services/ragSearch.js` (hybrid 0.7 vector + 0.3 FTS `french`, floors 0.12/0.2/×0.3).
  - Chatbot: `src/services/chatbotService.js` — FR system prompt + injected date, **8 read-only tools** (search_rag/search_threats/get_threat/search_alerts/search_activities/search_notes/get_stats/get_agent_context), bounded tool loop (tools off on last round). Routes: `src/routes/chat.routes.js` (`/api/chat`, SSE `?stream=1` with events `tool`/`final`/`error`, per-user rate limit + daily quota, injection detection log-only).
  - Voice batch: `src/services/voiceService.js` + `src/routes/voice.routes.js` (`/api/voice/stt|tts|voices|live-token`; multer 10 MB memory).
  - Voice live: `src/voice/live.js` — **WS mounted on the main HTTP server at `VOICE_LIVE_PATH` (default `/voice-live`)**, same-origin as the app (required by CSP `connect-src 'self'` and by Traefik TLS), started by `server.js` with the main `server` (only the upgrade listeners are closed on shutdown), auth via `?token=` (short JWT from `/api/voice/live-token`), Gemini Live (PCM 16 kHz), read-only voice tool subset.
  - AI routes mount lazily in `src/app.js` inside `try/catch` — missing `pg` or DB must never break the app/tests.
- Frontend: static HTML in `public/`, vanilla JS. Shared shell + API helper: `public/js/soc.js` (`window.SOC`). Per-page scripts: `public/js/{dashboard,agents,threats,alerts,activities,chat,settings,api-docs,login}.js`. `/chat` is the full-page chatbot view (Boron chat layout, no conversation sidebar): latest conversation reloaded from `/api/chat/conversations`, SSE streaming, tool chips, sources, dictation. Theme assets are prebuilt under `public/assets/` — do not regenerate.
- Assistant widget: `public/js/assistant.js` (loaded on every page except `/login` and `/chat`) — floating FAB + panel: chat SSE streaming with tool chips and sources, dictation (`SpeechRecognition`, fr-FR), push-to-talk (MediaRecorder → `/api/voice/stt` → chat → TTS playback), live voice (WS to `VOICE_LIVE_PATH` on the app origin, AudioContext ScriptProcessor PCM 16 kHz). Styles in `public/css/soc.css` (`.soc-assistant*`, `.soc-msg*`).
- Admin AI settings UI: `public/js/settings-ai.js` + `#settings-ai` block in `public/settings.html` (shown only for `role === 'admin'`; hidden on 403/500).
- API docs view (`/api-docs`): data generated by `scripts/build-api-docs.js` from `formatted_swagger_2_1.json` (full Swagger export of the console, ~33 Mo, committed at repo root). Output: `public/api-docs-data/index.json` + `cat/<slug>.json` (118 categories / 825 endpoints), served at `/api-docs/data/*` behind `requireApiAuth`. French overrides for hand-documented endpoints live in `public/js/api-catalog.js` (`SOC_API_CATALOG`, keyed by method+path) and are merged client-side in `public/js/api-docs.js`. Re-run `npm run docs:build` after refreshing the Swagger export.

## Env / config gotchas

- `src/config.js` reads `process.env` at load. Tests **must set env vars before `require('../src/app')`** (see `tests/api.test.js` top of file). Inject a fake client via `createApp({ client })` — do not point tests at a real console.
- `SESSION_SECRET` is **mandatory in production** (`config.js` throws). Dev uses an ephemeral secret and warns.
- `S1_URL` is normalized: scheme added if missing, `/web/api/v2.1` appended if absent. Mock servers must strip that prefix.
- `AUTH_DEV_LOGIN=true` is ignored when `NODE_ENV=production`. Requires `AUTH_DEV_USER` + `AUTH_DEV_PASSWORD`.
- Sampled KPIs: `S1_SAMPLE_LIMIT` (clamped 50–1000, default 1000). When totals exceed the sample, `sampled.*` is true and the UI prefixes `≈`. Do not treat sample counts as full inventory. **With the DB active, `sampled.*` is false and KPIs come from SQL aggregates** — the sample only feeds the « récents » lists (and everything when the sync is broken).
- Force refresh: `?refresh=1` on any list/overview endpoint bypasses the client cache — **and**, when the DB is enabled, first runs a delta sync (`DB_SYNC_REFRESH_MIN_MS`, default 10 s, throttles bursts).

## Security / CSP

- Helmet CSP is strict: no external CDNs, `script-src` allows `'self'` + `'unsafe-inline'`.
- Fonts are **self-hosted** (`public/assets/fonts` + `@font-face` in `public/css/soc.css`). Do **not** re-add Google Fonts `@import` to theme CSS — it was removed on purpose and will break CSP.
- Sessions are httpOnly JWT cookies (`soc_session`, HS256, issuer `soc-platform`).

## Tests

- Built-in `node:test` + `assert/strict`. API tests spin up an in-process fake S1 HTTP server and a real Express app on ephemeral ports.
- `tests/store.test.js` proves the DB read path (views served without touching S1), the delta filters, the reconciliation and the exact SQL KPIs; it seeds `soc_test` from scratch on every run and skips itself without PostgreSQL. `tests/overview.test.js` covers the sample path and the exact-aggregate path of `buildOverview`.
- Login in tests: dev user from env (`dev` / `dev-password` in `api.test.js`).
- Login rate limiter is active — raise `AUTH_RATE_LIMIT_MAX` in test env (already done).

## E2E / manual verification (optional)

`.verify/` holds a standalone mock S1 (`mock-s1.js`, port 3211, token `test-token`) and a headless Chrome check (`browser-check.js`, expects app on 3212 with dev login `dev`/`devpass`). Not part of `npm test`.

## Conventions

- Platform is **read-only** against SentinelOne (no isolate/kill/mitigate actions yet). The chatbot/voice tools are **read-only** too — never add write/action tools.
- Keep French for user-facing copy; error messages map S1 HTTP codes in `client.js`.
- `.env` and `*.log` are gitignored; copy `.env.example` for local config.
