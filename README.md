# DeerAger API
Hono + Postgres + S3 (Railway). Photo -> model -> deterministic rules -> saved scan.

## Deploy (Railway)
1. Add Postgres and a Bucket to the project; connect this repo (branch `main`).
2. Set variables from `.env.example` (`DATABASE_URL=${{Postgres.DATABASE_URL}}`, bucket refs, model keys + exact model ids).
3. First deploy runs `src/migrate.js`. Set `ADMIN_EMAIL`/`ADMIN_PASSWORD` once to seed the admin, then remove the password.
4. Stripe (keys live in the DB, editable in Admin > Stripe). `STRIPE_PUBLISHABLE_KEY` seeds the publishable key on first migrate. In the admin console paste the **secret** key, click Test connection, then Create webhook automatically. The Pro price is created in Stripe on first checkout and re-created when the price changes. Original notes: create a recurring price, paste its id into the Pro plan (`PUT /api/admin/plans/pro {"stripe_price_id":"price_..."}`), point the webhook at `/api/webhooks/stripe`.

## Benchmark the 3 models
Upload jaws, then `POST /api/admin/benchmark/:scanId {"truth_class":"2.5"}` for each lab-aged jaw. `GET /api/admin/benchmark/summary` ranks providers. Set `PRIMARY_MODEL` to the winner.

## Test
`MOCK_MODELS=1` returns canned model output. With Postgres and `node test/fake-s3.js` running: `node test/e2e.mjs` (34 checks).

## Not yet built
Email verification, password reset, rate limiting, PWA manifest with PNG icons. The rules thresholds in `src/rules.js` are uncalibrated until benchmarked.
