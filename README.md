# Deer Ager

Estimate a whitetail's age from jawbone photos, keep a private log of every buck (with hunt details), and estimate a Boone & Crockett score.
Bun + Hono + Postgres + S3 bucket + Stripe + Resend. One service serves the API and the web app.

## Flow
Splash → step 1 details (name, address, phone, email, password) → step 2 pick monthly/annual → Stripe Checkout (card, Apple Pay, Google Pay; 1-day free trial, card required) → the account activates when Stripe confirms the card → scan, score, log bucks. A confirmation email is sent but does not block access.
Free tier: hidden from the public. Admins create accounts (Admin > Users > Add a user) or grant free access to existing users; those accounts skip Stripe.
Cancel any time in Account (Stripe is updated). Annual subscribers keep their saved data for life; if a plan is not active nobody can scan new deer, and monthly subscribers' data is hidden until they resubscribe.

## Deploy on Railway
1. Add **Postgres** and a **Bucket** to the project, connect this repo (branch `main`). `railway.json` sets the start command and `/health` check.
2. Set the variables in `.env.example`. Set `APP_URL` to the public domain (e.g. https://deerager.com).
3. First start migrates the database and seeds the admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD` (remove the password variable after first login).
4. Sign in → **Admin > Settings**: paste the Stripe secret key, click *Test connection*, then *Create webhook automatically*; paste the Resend API key and sender (e.g. `Deer Ager <noreply@deerager.com>`), then *Send test*. Verify the domain in Resend (DNS records) so mail is delivered.
5. **Admin > Plans** sets trial length and prices; the Stripe price is created on first checkout (a price change creates a new one).

Single-file alternative (no GitHub): `node build.mjs` writes `dist/index.tsx`, a self-contained file that can run as a Railway Function.

## Analytics, SEO and storage
First-party, cookie-free analytics (Admin > Analytics): visitors, sources (referrer and ?utm_source=), pages/steps, devices, signups and conversions; no IPs are stored. The landing page is prerendered with title, description, canonical, Open Graph and FAQ/SoftwareApplication schema; `/robots.txt` and `/sitemap.xml` are served. Submit the sitemap in Google Search Console. Photos are re-encoded in the browser (strips GPS/EXIF), stored content-addressed in the bucket, saved before analysis so a failed analysis can be retried, and deleted with their scan. Admin > Settings > System check tests storage, Stripe, email and AI keys.

## Admin console
Overview cards are clickable: free trials, Pro subscribers, total scans (who scans the most), past due, unverified. Open any user to see details (never passwords), scans, bucks and emails; send a password reset or confirmation email, suspend, grant lifetime data. Users, plans, Stripe, Resend and the model benchmark are all managed there.

## Reports and models
Every scan runs all configured models (Claude, OpenAI, Gemini; set the keys and exact `MODEL_*` ids). The model with the highest confidence is the headline result; the printable report (Print / PDF, email, or link) shows the datapoints behind it and a comparison table. Turn comparison off in Admin > Settings to run one model. Benchmark accuracy with lab-aged jaws: `POST /api/admin/benchmark/:scanId {"truth_class":"2.5"}`, then `GET /api/admin/benchmark/summary`.

## Security and PCI
Card data never touches this server: payment uses Stripe-hosted Checkout and the Stripe billing portal (PCI SAQ A scope). Passwords are bcrypt (cost 12); API/webhook secrets are AES-256-GCM encrypted at rest; Stripe webhooks are signature-verified; email and reset tokens are stored hashed and single-use; auth endpoints are rate limited; responses carry CSP, HSTS, X-Frame-Options, nosniff and no-store headers; photos are private and served by short-lived signed URLs; users can only read their own bucks and scans (admins can read all). Complete the Stripe SAQ A attestation in your Stripe dashboard and keep Railway/GitHub access to the team that needs it.

## Tests
`MOCK_MODELS=1` returns canned model output. With Postgres, `node test/fake-s3.js` and the app running: `node test/e2e.mjs` (API, ~70 checks) and `node test/ui-smoke.mjs` (screens, needs jsdom).

## Not yet built
Rate limiting is in-memory (fine for one instance), PNG PWA icons, and the accuracy calibration of `classify()` in `src/app.ts` (thresholds are a first guess until benchmarked against lab-aged jaws).
