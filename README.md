# Deer Ager

Estimate a whitetail's age from jawbone or deer photos, tell the hunter whether the deer meets their minimum age, keep a private log of every buck (name, points, photos, scans, hunt details), and estimate a Boone & Crockett score.
Bun + Hono + Postgres + S3 bucket + Stripe + Resend. One service serves the API and the web app.

## Flow
Splash (logo links home when signed in, splash otherwise; back button top left) → step 1 details (name, address, phone, email, password) → step 2 pick monthly/annual → Stripe Checkout (card, Apple Pay, Google Pay; 1-day free trial, card required) → the account activates when Stripe confirms the card → scan, score, log bucks. The 1-day trial includes a limited number of scans (set in Admin > Plans). A confirmation email is sent but does not block access.
Free tier: hidden from the public. Admins create accounts (Admin > Users > Add a user) or grant free access to existing users; those accounts skip Stripe.
Cancel any time in Account (Stripe is updated). Annual subscribers keep their saved data for life; if a plan is not active nobody can scan new deer, and monthly subscribers' data is hidden until they resubscribe.

## Scans, results and the shoot / pass decision
Photo step: take a photo or upload (every photo prompt offers both); one photo is enough to start, and each photo is checked for quality. Modes: **jawbone** (most accurate), **live deer / trail camera** (weaker, confidence capped at 60%) and **antler photo** for a B&C estimate.
Each result shows: the age estimate, a chance for each age (0.5 through 6.5+), the confidence and why it is limited, why the AI reached the result, the tooth/body features it saw, other ages considered, photo notes, and what would firm it up.
**Hunting rules.** Hunters can save up to 8 rule sets (public land, club/lease, private): minimum age, points, inside spread, net B&C, season buck limit, does-first, legal antler rule and notes. The active set drives the "Can I shoot him?" card and a Shooter check on each buck (meets / doesn't meet / need more info). Bucks also record property type, property name and status (watching/passed/harvested).

**B&C score sheet.** Tape measurements saved on a buck produce a printable sheet laid out like the official typical-whitetail chart (points, spreads, main beams, G and H measurements, differences, gross and net). It prints or saves as PDF, emails, texts or shares as a link (`/b/<token>?sheet=bc`), and always says it is an estimate, not an official score, with blank lines for the official measurer.

**Partner API.** Other apps (such as hunting club software) can run scans through `/api/v1` with a per-partner key, hosted capture links, signed webhooks and member transfers, so deer follow the member between clubs. Admins manage partners in Admin > Partners. Full guide: `docs/INTEGRATION.md`. Club, member and season management stay in the partner app.

**Share links** (scan `/s/…` and buck sheet `/b/…`) include the photos. Photos are served through the link itself, so they keep working as long as the link does and nothing else in the bucket is exposed.

**Can I shoot him?** The hunter picks a minimum age (3.5+, 4.5+, 5.5+, 6.5+; remembered). The card gives the chance he meets it: 70%+ looks old enough, 50-70% leaning old enough but not firm, 30-50% leaning too young, under 30% probably too young. Probabilities blend the AI's own distribution with a population prior, trusting the photos less when quality is low (cap 90% jaw, 60% deer photo). The cutoffs and prior are first guesses until calibrated against lab-aged jaws. Everything is labelled an estimate.
If photo storage is down the analysis still runs and the result says the photos were not saved.

## Bucks
Name (e.g. Lightning), points (e.g. 8), date, location, stand, wind, temperature, rut phase, tactics, notes. Attach photos (jawbone, field, rack, mount), age scans (new or already-run) and a B&C score to a buck; any result can be saved to a buck, and scans can be removed from one. Bucks are private to their owner (admins can read all).

## Data sheets and sharing
Each buck has a one-page data sheet (buck photo in the upper right, name, points, age and B&C estimates, hunt details, scans, photos). From the sheet the owner can print / save a PDF, email it (up to 5 addresses), text it (opens the phone's messages with a link) or copy a link; the link page is public but unlisted and read-only. An owner can also share a sheet with another Deer Ager member by email: it appears under Bucks > Shared with me, read-only, and the owner can stop sharing any time.

## Deploy on Railway
1. Add **Postgres** and a **Bucket** to the project, connect this repo (branch `main`; pushes redeploy). `railway.json` sets the start command and `/health` check. Custom domains must target the port the app listens on (8080 on Railway).
2. Set the variables in `.env.example` (in Railway use references: `${{Postgres.DATABASE_URL}}` and the bucket's `${{<bucket>.ENDPOINT}}`, `BUCKET`, `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`). Set `APP_URL` to the public domain (e.g. https://deerager.com).
3. First start migrates the database and seeds the admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD` (remove the password variable after first login).
4. Sign in → **Admin > Settings**: paste the Stripe secret key, click *Test connection*, then *Create webhook automatically*; add the Resend key (or set `RESEND_API_KEY` in Railway) and sender (e.g. `Deer Ager <noreply@deerager.com>`), then *Send test*. Verify the domain in Resend (4 DNS records at your registrar) so mail is delivered. Use matching Stripe keys: test publishable + test secret, or live + live.
5. **Admin > Plans** sets trial length and prices; the Stripe price is created on first checkout (a price change creates a new one).

Single-file alternative (no GitHub): `node build.mjs` writes `dist/index.tsx`, a self-contained file that can run as a Railway Function.

## Analytics, SEO and storage
First-party, cookie-free analytics (Admin > Analytics): visitors, sources (referrer and ?utm_source=), pages/steps, devices, signups and conversions; no IPs are stored. The landing page is prerendered with title, description, canonical, Open Graph and FAQ/SoftwareApplication schema; `/robots.txt` and `/sitemap.xml` are served. Submit the sitemap in Google Search Console. Photos are re-encoded in the browser (strips GPS/EXIF), stored content-addressed in the bucket, saved before analysis so a failed analysis can be retried, and deleted with their scan. Admin > Settings > System check tests storage, Stripe, email and AI keys.

## Admin console
Overview cards are clickable: free trials, Pro subscribers, total scans (who scans the most), past due, unverified. In Analytics, Visitors, Page views, every day, source, page, device and country is clickable: it lists the visitors and where each came from and went next. The Models tab explains accuracy grading: enter a lab-confirmed true age on a jaw scan and it shows each model's exact and within-1-year accuracy. Open any user to see details (never passwords), scans, bucks and emails; send a password reset or confirmation email, suspend, grant lifetime data. Users, plans, Stripe, Resend and the model benchmark are all managed there.

## Reports and models
Every scan runs all configured models (Claude, OpenAI, Gemini; set the keys and exact `MODEL_*` ids). Currently only Claude is configured. With several, the model with the highest confidence is the headline result and the printable report (Print / PDF, email, or link) shows a comparison table; with one it is a single-model report. Reports always include the datapoints behind the result. Turn comparison off in Admin > Settings to run one model. Benchmark accuracy with lab-aged jaws: `POST /api/admin/benchmark/:scanId {"truth_class":"2.5"}`, then `GET /api/admin/benchmark/summary`.

## Security and PCI
Card data never touches this server: payment uses Stripe-hosted Checkout and the Stripe billing portal (PCI SAQ A scope). Passwords are bcrypt (cost 12); API/webhook secrets are AES-256-GCM encrypted at rest; Stripe webhooks are signature-verified; email and reset tokens are stored hashed and single-use; auth endpoints are rate limited; responses carry CSP, HSTS, X-Frame-Options, nosniff and no-store headers; photos are private and served by short-lived signed URLs; users can only read their own bucks and scans (admins can read all). Complete the Stripe SAQ A attestation in your Stripe dashboard and keep Railway/GitHub access to the team that needs it.

## Tests
`MOCK_MODELS=1` returns canned model output. With Postgres, `node test/fake-s3.js` and the app running: `node test/e2e.mjs` (API, ~110 checks), `node test/ui-smoke.mjs` (screens, needs jsdom) and `test/capture.mjs` (photo to results, run from a folder with jsdom installed).

## Not yet built
**Hunting club tier** (club accounts, members whose deer follow them between clubs, a copy of each deer record kept by the club they left, an end-of-season view with photos and data, and an API for the separate club-management software). Rate limiting is in-memory (fine for one instance), PNG PWA icons, and the accuracy calibration of `classify()` in `src/app.ts` (thresholds are a first guess until benchmarked against lab-aged jaws).
