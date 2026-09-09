# Super Clean — A+B final pre-deployment check

## A — integration
- Current V32 frontend assets merged with the A+B backend/enhancement layer.
- Express 5 catch-all syntax verified.
- Node syntax verified for `server.js`, `public/app.js`, and `public/ab-enhancements.js`.
- A+B migration is included.
- Planned/actual pickup, measurement-at-pickup, routes/vehicles/attempts, cashier payments, and memorandum settings are included in the A+B migration/backend.
- Backup support for invoice `due_date` is present in the integrated backend.

## B — mobile readiness
- The A+B enhancement CSS is included and loaded by the real `index.html`.
- The real V32 frontend is used; the standalone prototype is not used as the application.
- Static mobile contract checks pass.
- A real PostgreSQL end-to-end run and a browser screenshot test require the runtime dependencies/database to be available. This package therefore does **not** claim production/runtime PASS.

## Deployment gate
Do not deploy to GitHub/Railway as production until the application is run with PostgreSQL and the mobile browser flow is exercised end-to-end.
