# ELAI Dashboard - Current TODO

This file reflects the active architecture of the dashboard.

## Active Stack

- Express server
- tRPC API layer
- Socket.IO real-time updates
- MySQL via Drizzle ORM
- React + Vite frontend

## Completed

- [x] Direct dashboard alert ingestion via `POST /api/alerts`
- [x] Database-backed alert persistence
- [x] Socket.IO live alert streaming
- [x] React dashboard with alert feed, table, SHAP card, and SOC actions
- [x] On-demand deep analysis endpoint
- [x] Deterministic fallback when Ollama is unavailable
- [x] File-based alert ingestion moved to optional backfill mode
- [x] TypeScript check passing with `npm run check`

## Next Recommended Work

- [ ] Add an end-to-end integration test for alert creation -> DB -> websocket -> UI
- [ ] Add a dedicated `.env.example`
- [ ] Add a dashboard health endpoint for DB, websocket, and Ollama availability
- [ ] Replace simulated system metrics with real host telemetry if desired
- [ ] Implement real PDF/CSV export instead of placeholders
- [ ] Add deduplication logic at the database level if multiple ingestion paths are used
- [ ] Improve authentication/authorization if the app is exposed outside a demo environment

## Operational Notes

- Primary ingestion path: direct HTTP post from `FYP/inference.py`
- Optional ingestion path: JSON file backfill, enabled only with `ENABLE_FILE_ALERT_INGESTION=true`
- Deep analysis works without Ollama, but uses fallback summaries until the local model is installed
