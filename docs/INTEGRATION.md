# Deer Ager partner integration guide

Deer Ager can run inside another app (for example hunting club management software). The partner app owns clubs, members and seasons. Deer Ager is the aging engine: it takes photos and returns an age estimate, probabilities, a Boone & Crockett estimate and a "meets my rules" check.

All results are estimates. Show the `disclaimer` text wherever you show a result.

## 1. Get a key

An admin creates the partner in **Admin > Partners**. You receive:

- an API key starting with `dk_live_` (shown once; rotate it any time),
- a webhook signing secret starting with `whsec_`,
- a monthly scan limit (0 means unlimited).

Send the key on every call: `Authorization: Bearer dk_live_...`. Base URL: `https://www.deerager.com/api/v1`.

## 2. Your IDs travel with each deer

Pass your own identifiers on every scan. Deer Ager stores them and lets you search by them:

| Field | Meaning |
| --- | --- |
| `member_id` | The hunter in your system. The deer belongs to this person. |
| `deer_id` | Your record for the deer (optional). |
| `club_id` | The club the deer is currently attached to. |
| `points` | Antler points (0 to 40). |
| `spread`, `net` | Inside spread and net B&C in inches, if known. |
| `rules` | The hunting rules to check against (see below). |

`rules` is a JSON object: `min_age` (2.5, 3.5, 4.5, 5.5 or 6.5), `min_points`, `min_spread`, `min_net`, `season_limit`, `does_first`, `antler_rule`, `notes`.

## 3. Run a scan (you collect the photos)

`POST /scans` as `multipart/form-data`:

- `mode`: `jaw`, `deer` or `bc`
- `photos`: 1 to 8 image files, each under 4.9 MB (resize on the phone first)
- optional: `member_id`, `deer_id`, `club_id`, `points`, `spread`, `net`, `rules`

The call waits for the analysis (10 to 40 seconds) and returns:

```json
{
  "id": "uuid", "mode": "jaw", "status": "complete",
  "class": "Middle", "range": "Most likely 4.5 years (likely 2.5 to 5.5)", "confidence": 82,
  "age": { "best": "4.5", "low": "2.5", "high": "5.5", "probabilities": { "3.5": 24.5, "4.5": 35.9 } },
  "needs_more_photos": false, "issues": [], "missing": [],
  "rules": { "meets": "no", "checks": [ { "rule": "min_points", "required": 8, "value": 6, "status": "no" } ], "notes": [] },
  "member_id": "mem_1", "deer_id": "deer_9", "club_id": "clubA", "points": 6,
  "report_url": "https://www.deerager.com/s/...", "disclaimer": "Estimate only..."
}
```

`rules.meets` is `yes`, `no` or `unsure`. A rule with missing data (for example no spread) is `unknown` and makes the overall answer `unsure`. The age check says `yes` at 70% or more chance the deer meets the minimum age, `no` at 30% or less, and `unsure` in between.

If `needs_more_photos` is true, ask the hunter for clearer photos and send a new scan.

`report_url` is a public, printable report that includes the photos. Anyone with the link can open it, so treat it like a share link.

Errors: `401` bad key, `429 limit_reached` (monthly cap), `400 invalid_input`, `502/503` analysis problem (the photos are saved; retry).

## 4. Let Deer Ager collect the photos (hosted capture)

If you do not want to build the camera flow, ask for a capture link and open it in a browser or web view:

`POST /capture-links` with JSON `{ "mode": "jaw", "member_id": "...", "deer_id": "...", "club_id": "...", "rules": {...}, "return_url": "https://yourapp.com/deer/123", "expires_hours": 24, "max_uses": 3 }`

You get `{ "url": "https://www.deerager.com/c/..." }`. The hunter takes the guided photos, sees the full report, and a "Back" button returns them to `return_url?scan_id=...` (https only). No Deer Ager login is needed. Get the result through the webhook, or `GET /scans?member_id=...`.

## 5. Webhooks

Set a webhook URL (https) in Admin > Partners. Deer Ager sends `POST` with JSON `{ "id", "type": "scan.completed", "created", "data": <scan object> }` for every finished scan, and retries once after 5 seconds.

Verify the signature header `Deerager-Signature: t=<unix time>,v1=<hex>`. The value is HMAC-SHA256 of `"<t>.<raw body>"` with your webhook secret. Reject anything older than five minutes.

## 6. Read and update

- `GET /scans/{id}`: one scan.
- `GET /scans?member_id=&deer_id=&club_id=&limit=`: search (newest first).
- `PATCH /scans/{id}`: update `member_id`, `deer_id`, `club_id`, `points`, `spread`, `net`, `rules`. The rules check is recalculated on the next read.
- `GET /me`: your name, monthly limit and usage this month.

## 7. Deer follow the member between clubs

Deer belong to the member, not the club. When a member moves from club A to club B, call:

`POST /members/{member_id}/transfer` with `{ "from_club": "clubA", "to_club": "clubB" }`

Every scan for that member in club A moves to club B (omit `from_club` to move all of them). Your software can then keep a snapshot copy for the club you left, and build the end-of-season view and printable report from `GET /scans?club_id=...` plus the `report_url` links.

## Suggested build order

1. Run `POST /scans` from your server with test photos.
2. Add the webhook receiver and signature check.
3. Add the hosted capture link for mobile use.
4. Add transfers and the end-of-season screens in your app.
