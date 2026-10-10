# Elsewhere Pipeline Desk

Standalone page for the Elsewhere Partners deal pipeline. Shows every scored company with the
factor-by-factor reasoning, lets anyone with the link ask Claude Opus about a score, and has a
**Refresh from tracker** button that reads the IC tracker Google Doc, scores companies that are
not on the board yet, and publishes them.

No Claude account needed for viewers. Static page on GitHub Pages plus a small Cloudflare Worker
that holds the keys and the live board.

```
index.html            the app
data/companies.json   seed board (used until the live board exists, and as the first seed for it)
worker/               Cloudflare Worker: Claude proxy, Google Docs reader, live board in KV
```

## What the refresh button does, and does not do

1. Reads the latest tracker text through Google's Docs API, as you (see step 3).
2. Splits it into company sections (the `Financial Profile // Sector Fit // Deal Dynamics` marker).
3. Compares names against the live board. Names already on the board are left alone.
4. Scores each new name with Claude Opus against rubric v3, three at a time, showing
   "updating · scoring 2-4 of 7 · Syteca" in the header while it runs.
5. Appends them to the live board, re-ranks, and publishes. New rows carry a blue tick and a
   **Pitch-scored · tracker refresh** badge, and the **New** filter shows just them.

It does **not** run the independent verification pass (the multi-source research that checks
filings, funding databases and competitors). Everything the button adds is pitch-scored from the
tracker text, the same status as any other unverified row. Verification stays a separate step.

Refresh needs the access code, so a viewer with only the link can read but cannot trigger spend.

---

## 1. Deploy the Worker

```bash
cd worker
npm install
npx wrangler login

npx wrangler kv namespace create BOARD        # prints an id; paste it into wrangler.toml
npx wrangler secret put ANTHROPIC_API_KEY
npx wrangler secret put ACCESS_CODE           # any phrase; share it with the deal team
npx wrangler deploy
```

Edit `wrangler.toml` first: set `ALLOWED_ORIGINS` and `PAGES_ORIGIN` to your GitHub Pages
address, and paste the KV namespace id. `TRACKER_DOC_ID` is already the IC tracker.

`curl https://<worker>/api/health` should return `{"ok":true,...,"refresh":false,"kv":true}`.
`refresh` turns true after step 3.

## 2. Publish the page

Push this folder to a GitHub repo, turn on Pages (Settings → Pages → main, root). Then open
`index.html`, set `const DEFAULT_PROXY = "https://<your-worker>.workers.dev"`, and push again.
Viewers now get the live board automatically.

## 3. Give the Worker read access to the tracker

The doc is private, so the Worker reads it with a Google credential. Pick one.

### Option A: service account (use this if you can share the doc)

1. In Google Cloud Console create a project, enable the **Google Docs API**.
2. IAM → Service Accounts → Create. No roles needed. Create a JSON key and download it.
3. Open the tracker in Google Docs → Share → add the service account's email
   (`something@project.iam.gserviceaccount.com`) as **Viewer**.
4. `npx wrangler secret put GOOGLE_SA_KEY` and paste the entire JSON file contents.
5. `npx wrangler deploy`.

### Option B: your own Google sign-in (use this if you can only view the doc)

1. In Google Cloud Console create a project, enable the **Google Docs API**, configure the OAuth
   consent screen (External, add yourself as a test user), then create an **OAuth client ID** of
   type Desktop app. Note the client id and secret.
2. Get a refresh token once. Easiest: https://developers.google.com/oauthplayground, gear icon →
   "Use your own OAuth credentials", scope `https://www.googleapis.com/auth/documents.readonly`,
   authorize with the Google account that can open the tracker, exchange the code, copy the
   refresh token.
3. ```
   npx wrangler secret put GOOGLE_OAUTH_CLIENT_ID
   npx wrangler secret put GOOGLE_OAUTH_CLIENT_SECRET
   npx wrangler secret put GOOGLE_OAUTH_REFRESH_TOKEN
   npx wrangler deploy
   ```

Either way, `/api/health` now reports `"refresh":true` and the button lights up.

## 4. First refresh

Open the page, click the connection pill, enter the access code, Save. Click **Refresh from
tracker**. The first run seeds the live board from `data/companies.json`, reads the tracker, and
scores anything new. Later runs only score names that are not already on the board.

To wipe the live board and reseed from the static file:
`curl -X POST -H "X-Access-Code: <code>" https://<worker>/api/board/reset`

## Keeping the verified rows in sync

The live board in KV is now the source of truth for viewers. When a verification pass changes a
row (new score, verified badge, updated reasoning), regenerate `data/companies.json`, push it,
then hit `/api/board/reset` and refresh once. The reset is instant; the refresh reseeds from the
new file and picks up anything the tracker has added since.

## Cost

A refresh that finds N new companies makes N Opus calls of roughly 6-9k tokens in and 2k out,
a few cents each. A refresh that finds nothing new costs one Docs API read and no Claude calls.
Questions in the Ask panel are a few cents each as before.

## Running locally

`python3 -m http.server 8000` then open http://localhost:8000.
