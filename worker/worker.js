/**
 * Elsewhere Pipeline Desk - API proxy + tracker refresh
 *
 * Secrets:  ANTHROPIC_API_KEY, SESSION_SECRET (random string; signs sign-in sessions),
 *           ACCESS_CODE (optional admin override for curl),
 *           GOOGLE_OAUTH_CLIENT_ID + GOOGLE_OAUTH_CLIENT_SECRET + GOOGLE_OAUTH_REFRESH_TOKEN
 *             (refresh token granted BOTH documents.readonly and gmail.send)
 *           or GOOGLE_SA_KEY for the tracker only (then email needs the OAuth trio anyway)
 * Vars:     ALLOWED_ORIGINS, PAGES_ORIGIN, TRACKER_DOC_ID, ALLOWED_EMAILS, MAIL_FROM,
 *           SESSION_DAYS (default 30), MODEL (optional), MAX_TOKENS
 * Binding:  BOARD (KV namespace; also holds sign-in codes and rate limits)
 *
 * Sign-in: POST /api/auth/request {email} -> 6-digit code emailed (10 min, 5 tries)
 *          POST /api/auth/verify {email, code} -> {token} (HMAC-signed, SESSION_DAYS)
 *          GET  /api/auth/me -> {email, exp}
 *          Every data route needs Authorization: Bearer <token> (or X-Access-Code for admin).
 */

const ANTHROPIC = "https://api.anthropic.com/v1";
const API_VERSION = "2023-06-01";
const OPUS_PREFERENCE = ["claude-opus-5", "claude-opus-4-8", "claude-opus-4-6", "claude-opus-4-5"];
const SCORE_BATCH = 3; // companies scored per /api/refresh call; the page loops until done

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    if (url.pathname === "/api/health") {
      return json({ ok: true, model: env.MODEL || "auto", signIn: true, mail: !!(env.GOOGLE_OAUTH_REFRESH_TOKEN && env.MAIL_FROM),
        refresh: !!(env.GOOGLE_SA_KEY || env.GOOGLE_OAUTH_REFRESH_TOKEN), kv: !!env.BOARD }, 200, cors);
    }
    if (!allowed(origin, env)) return json({ error: "Origin not allowed" }, 403, cors);

    // Sign-in (no session needed)
    if (url.pathname === "/api/auth/request" && request.method === "POST") return authRequest(request, env, cors);
    if (url.pathname === "/api/auth/verify" && request.method === "POST") return authVerify(request, env, cors);

    // Everything below needs a signed-in session (or the admin access code for curl)
    const who = await authenticate(request, env);
    if (!who) return json({ error: "Sign in required.", code: "unauthenticated" }, 401, cors);

    if (url.pathname === "/api/auth/me") return json({ email: who.email, exp: who.exp, admin: !!who.admin }, 200, cors);

    if (url.pathname === "/api/board" && request.method === "GET") {
      if (!env.BOARD) return json({ error: "No KV binding" }, 404, cors);
      const raw = await env.BOARD.get("board");
      if (!raw) return json({ error: "empty" }, 404, cors);
      return new Response(raw, { status: 200, headers: { ...cors, "content-type": "application/json", "cache-control": "no-store" } });
    }

    // Replace the whole board (used to push a regenerated seed); body = full board JSON
    if (url.pathname === "/api/board/import" && request.method === "POST") {
      if (!env.BOARD) return json({ error: "No KV binding" }, 400, cors);
      let b; try { b = await request.json(); } catch { return json({ error: "Bad JSON" }, 400, cors); }
      if (!Array.isArray(b.companies)) return json({ error: "Not a board" }, 400, cors);
      await env.BOARD.put("board", JSON.stringify(b)); await env.BOARD.delete("refresh");
      return json({ ok: true, count: b.companies.length }, 200, cors);
    }

    if (url.pathname === "/api/models") {
      const r = await fetch(ANTHROPIC + "/models?limit=100", { headers: authHeaders(env) });
      return new Response(await r.text(), { status: r.status, headers: { ...cors, "content-type": "application/json" } });
    }

    if (url.pathname === "/api/chat" && request.method === "POST") return chat(request, env, ctx, cors);

    if (url.pathname === "/api/refresh" && request.method === "POST") return refresh(request, env, ctx, cors);

    if (url.pathname === "/api/board/reset" && request.method === "POST") {
      if (!env.BOARD) return json({ error: "No KV binding" }, 400, cors);
      // drops the rows added by tracker refresh and the refresh state; curated rows stay
      const raw = await env.BOARD.get("board"); const b = raw ? JSON.parse(raw) : null;
      if (b) { b.companies = b.companies.filter((c) => c.source !== "tracker-refresh"); b.companies.forEach((c, i) => (c.rank = i + 1)); b.count = b.companies.length; await env.BOARD.put("board", JSON.stringify(b)); }
      await env.BOARD.delete("refresh");
      return json({ ok: true, count: b ? b.companies.length : 0 }, 200, cors);
    }

    return json({ error: "Not found" }, 404, cors);
  },
};


/* ---------------- sign-in: emailed passcode, signed session ---------------- */
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = (s) => b64u(enc.encode(s));
const unb64u = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return atob(s); };
async function sha256(s) { return b64u(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function hmac(secret, data) { const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(data))); }
function allowedEmail(email, env) {
  const list = String(env.ALLOWED_EMAILS || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  const e = String(email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return false;
  return list.some((a) => (a.startsWith("@") ? e.endsWith(a) : e === a));
}
async function authRequest(request, env, cors) {
  if (!env.BOARD || !env.SESSION_SECRET) return json({ error: "Sign-in is not configured on the Worker (BOARD + SESSION_SECRET)." }, 500, cors);
  let body = {}; try { body = await request.json(); } catch {}
  const email = String(body.email || "").trim().toLowerCase();
  if (!allowedEmail(email, env)) return json({ error: "That email address is not on the access list." }, 403, cors);
  const rlKey = "auth:rl:" + email; const n = Number((await env.BOARD.get(rlKey)) || 0);
  if (n >= 5) return json({ error: "Too many codes requested. Try again in 15 minutes." }, 429, cors);
  await env.BOARD.put(rlKey, String(n + 1), { expirationTtl: 900 });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  await env.BOARD.put("auth:code:" + email, JSON.stringify({ h: await sha256(code + "|" + env.SESSION_SECRET), tries: 0, exp: Date.now() + 10 * 60 * 1000 }), { expirationTtl: 600 });
  try { await sendCodeEmail(email, code, env); }
  catch (e) { console.error("sendCodeEmail failed: " + e.message); return json({ error: "Could not send the email: " + e.message.slice(0, 200) }, 502, cors); }
  return json({ ok: true }, 200, cors);
}
async function authVerify(request, env, cors) {
  let body = {}; try { body = await request.json(); } catch {}
  const email = String(body.email || "").trim().toLowerCase(); const code = String(body.code || "").replace(/\D/g, "");
  const key = "auth:code:" + email; const rec = JSON.parse((await env.BOARD.get(key)) || "null");
  if (!rec || rec.exp < Date.now()) return json({ error: "Code expired or not requested. Ask for a new one." }, 401, cors);
  if (rec.tries >= 5) { await env.BOARD.delete(key); return json({ error: "Too many attempts. Ask for a new code." }, 401, cors); }
  if (!timingSafeEqual(rec.h, await sha256(code + "|" + env.SESSION_SECRET))) { rec.tries++; await env.BOARD.put(key, JSON.stringify(rec), { expirationTtl: 600 }); return json({ error: "That code is not right (" + (5 - rec.tries) + " tries left)." }, 401, cors); }
  await env.BOARD.delete(key);
  const days = Number(env.SESSION_DAYS || 30); const exp = Date.now() + days * 86400 * 1000;
  const payload = b64uStr(JSON.stringify({ email, exp, iat: Date.now() }));
  const token = payload + "." + (await hmac(env.SESSION_SECRET, payload));
  return json({ token, email, exp }, 200, cors);
}
async function authenticate(request, env) {
  const code = request.headers.get("X-Access-Code") || "";
  if (env.ACCESS_CODE && code && timingSafeEqual(code, env.ACCESS_CODE)) return { email: "admin", admin: true, exp: 0 };
  const h = request.headers.get("Authorization") || ""; const m = /^Bearer\s+(.+)$/i.exec(h); if (!m || !env.SESSION_SECRET) return null;
  const [payload, sig] = m[1].split("."); if (!payload || !sig) return null;
  if (!timingSafeEqual(sig, await hmac(env.SESSION_SECRET, payload))) return null;
  let p; try { p = JSON.parse(unb64u(payload)); } catch { return null; }
  if (!p.email || !p.exp || p.exp < Date.now()) return null;
  if (!allowedEmail(p.email, env)) return null; // revoke by editing ALLOWED_EMAILS
  return { email: p.email, exp: p.exp };
}
async function sendCodeEmail(to, code, env) {
  if (!env.GOOGLE_OAUTH_REFRESH_TOKEN || !env.MAIL_FROM) throw new Error("MAIL_FROM and the Google OAuth secrets (with gmail.send scope) are required");
  const token = await googleToken(env);
  const subject = "Pipeline Desk sign-in code: " + code;
  const text = "Your Pipeline Desk sign-in code is " + code + "\n\nIt expires in 10 minutes. If you did not request it, ignore this email.\n";
  const raw = ["From: Pipeline Desk <" + env.MAIL_FROM + ">", "To: " + to, "Subject: " + subject, "MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8", "", text].join("\r\n");
  const r = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", { method: "POST", headers: { Authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify({ raw: b64uStr(raw) }) });
  if (!r.ok) throw new Error("Gmail API " + r.status + " " + (await r.text()).slice(0, 200));
}

/* ---------------- chat (unchanged behaviour) ---------------- */
async function chat(request, env, ctx, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: "Bad JSON" }, 400, cors); }
  const system = String(body.system || "").slice(0, 200000);
  const messages = Array.isArray(body.messages) ? body.messages.slice(-24) : [];
  if (!messages.length) return json({ error: "No messages" }, 400, cors);
  for (const m of messages) if (typeof m.content === "string" && m.content.length > 20000) m.content = m.content.slice(0, 20000);
  const model = env.MODEL || (await pickOpus(env));
  const payload = { model, max_tokens: Number(env.MAX_TOKENS || 2000), system, messages, stream: true };
  if (body.webSearch) payload.tools = [{ type: "web_search_20250305", name: "web_search", max_uses: 5 }];
  const up = await fetch(ANTHROPIC + "/messages", { method: "POST", headers: { ...authHeaders(env), "content-type": "application/json" }, body: JSON.stringify(payload) });
  if (!up.ok) return json({ error: "Anthropic error " + up.status, detail: (await up.text()).slice(0, 1200), model }, up.status, cors);
  return new Response(up.body, { status: 200, headers: { ...cors, "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache, no-transform", "x-model-used": model } });
}

/* ---------------- refresh ---------------- */
/*
  Flow (incremental so the page can show progress):
   1. If KV has no board, seed it from PAGES_ORIGIN/data/companies.json.
   2. Fetch the tracker text via Google Docs API, split into company blocks.
   3. Diff against the board by normalised name. New names -> queue.
   4. Score up to SCORE_BATCH queued companies with Claude, append as pitch-scored rows.
   5. Return {phase, done, added, remaining, ...}. Page re-calls until done.
*/
async function refresh(request, env, ctx, cors) {
  if (!env.BOARD) return json({ error: "Live board needs a KV binding (BOARD) in wrangler.toml" }, 400, cors);
  if (!env.TRACKER_DOC_ID) return json({ error: "TRACKER_DOC_ID not set" }, 400, cors);
  let body = {}; try { body = await request.json(); } catch {}

  let board = JSON.parse((await env.BOARD.get("board")) || "null");
  if (!board) {
    const seedUrl = (env.PAGES_ORIGIN || "").replace(/\/+$/, "") + "/data/companies.json";
    const r = await fetch(seedUrl);
    if (!r.ok) return json({ error: "Live board is empty and the seed could not be fetched from " + seedUrl }, 500, cors);
    board = await r.json();
    await env.BOARD.put("board", JSON.stringify(board));
  }

  let state = JSON.parse((await env.BOARD.get("refresh")) || "null");

  // Phase 1: crawl + diff (only on the first call of a run, or when asked to restart)
  if (!state || body.restart || state.done) {
    let text;
    try { text = await fetchDocText(env); }
    catch (e) { return json({ error: "Could not read the tracker: " + e.message }, 502, cors); }
    const all = splitCompanies(text);
    const blocks = applyCutoff(all, env.MIN_WEEK);
    // self-heal: a refresh row with no factor scores is a failed score; drop it so it gets redone
    const before = board.companies.length;
    board.companies = board.companies.filter((c) => !(c.source === "tracker-refresh" && !(c.score > 0)));
    if (board.companies.length !== before) await env.BOARD.put("board", JSON.stringify(board));
    const have = new Set(board.companies.map((c) => norm(c.name)));
    const queue = [];
    const seen = new Set();
    for (const b of blocks) {
      const k = norm(b.name);
      if (!k || have.has(k) || seen.has(k)) continue;
      seen.add(k); queue.push(b);
    }
    state = { startedAt: new Date().toISOString(), found: blocks.length, total: all.length, queue, added: [], failed: [], done: queue.length === 0 };
    await env.BOARD.put("refresh", JSON.stringify(state));
    if (state.done) {
      board.lastRefresh = { at: state.startedAt, found: blocks.length, added: 0 };
      await env.BOARD.put("board", JSON.stringify(board));
      return json({ phase: "done", done: true, found: blocks.length, total: all.length, added: [], remaining: 0 }, 200, cors);
    }
    return json({ phase: "crawled", done: false, found: blocks.length, total: all.length, remaining: queue.length, next: queue.slice(0, SCORE_BATCH).map((b) => b.name) }, 200, cors);
  }

  // Phase 2: score a batch
  const model = env.MODEL || (await pickOpus(env));
  const batch = state.queue.splice(0, SCORE_BATCH);
  const results = await Promise.allSettled(batch.map((b) => scoreOne(b, board, model, env)));
  results.forEach((res, i) => {
    const b = batch[i];
    if (res.status === "fulfilled") { board.companies.push(res.value); state.added.push({ name: res.value.name, score: res.value.score }); }
    else { const msg = String(res.reason?.message || res.reason).slice(0, 300); console.error("refresh: failed " + b.name + ": " + msg); state.failed.push({ name: b.name, error: msg }); }
  });
  // Re-rank
  board.companies.sort((a, b) => b.score - a.score);
  board.companies.forEach((c, i) => (c.rank = i + 1));
  board.count = board.companies.length;
  state.done = state.queue.length === 0;
  if (state.done) {
    board.updated = new Date().toISOString().slice(0, 10);
    board.lastRefresh = { at: state.startedAt, found: state.found, added: state.added.length, failed: state.failed.length };
  }
  await env.BOARD.put("board", JSON.stringify(board));
  await env.BOARD.put("refresh", JSON.stringify(state));
  return json({ phase: state.done ? "done" : "scoring", done: state.done, added: state.added, failed: state.failed,
    remaining: state.queue.length, next: state.queue.slice(0, SCORE_BATCH).map((b) => b.name), model }, 200, cors);
}

/* Best-effort repair of model-written JSON: escapes raw newlines/tabs inside strings and
   quotes that appear inside a string without being followed by a structural character. */
function repairJson(src) {
  let out = "", inStr = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (!inStr) { out += c; if (c === '"') inStr = true; continue; }
    if (c === "\\") { out += c + (src[i + 1] ?? ""); i++; continue; }
    if (c === "\n") { out += "\\n"; continue; }
    if (c === "\r") { continue; }
    if (c === "\t") { out += "\\t"; continue; }
    if (c === '"') {
      let k = i + 1; while (k < src.length && /\s/.test(src[k])) k++;
      const nxt = src[k];
      if (nxt === undefined || nxt === "," || nxt === "}" || nxt === "]" || nxt === ":") { out += c; inStr = false; }
      else out += '\\"';
      continue;
    }
    out += c;
  }
  return out;
}
const SCORE_TOOL = {
  name: "record_score",
  description: "Record the Elsewhere rubric score for one company. Every field is required; use empty strings or [] when the document is silent.",
  input_schema: {
    type: "object",
    properties: {
      hq: { type: "string" },
      sector: { type: "string", description: "one line: category and the durability situation" },
      what: { type: "string", description: "one or two sentences on what the product does, concretely" },
      financials: { type: "string", description: "the numbers as stated, compact, flagged as stated" },
      factors: { type: "object", properties: Object.fromEntries(["A", "B", "C", "D", "E"].map((k) => [k, { type: "object", properties: { score: { type: "integer", minimum: 0, maximum: 100 }, reason: { type: "string" } }, required: ["score", "reason"] }])), required: ["A", "B", "C", "D", "E"] },
      archetype: { type: "string" },
      founderTransition: { type: "string" },
      checkAbsorbability: { type: "string" },
      aiTailwinds: { type: "string" },
      aiHeadwinds: { type: "string" },
      financialProfile: { type: "string" },
      dealDynamics: { type: "string" },
      unverified: { type: "array", items: { type: "string" } },
      read: { type: "string", description: "two sentences: the Elsewhere read and the one question that decides it" },
    },
    required: ["hq", "sector", "what", "financials", "factors", "archetype", "founderTransition", "checkAbsorbability", "aiTailwinds", "aiHeadwinds", "financialProfile", "dealDynamics", "unverified", "read"],
  },
};
async function scoreOne(block, board, model, env) {
  let lastErr;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try { return await scoreOnce(block, board, model, env, attempt); }
    catch (e) { lastErr = e; console.error("scoreOne attempt " + attempt + " failed for " + block.name + ": " + e.message); }
  }
  throw lastErr;
}
async function scoreOnce(block, board, model, env, attempt) {
  const prompt = RUBRIC + "\n\nCALIBRATION FROM THE CURRENT BOARD (top 12 and bottom 4, name = score [A B C D E]):\n" + calibration(board) +
    "\n\nDOCUMENT (one company section from the Elsewhere IC tracker, week " + block.week + "):\n" + block.text.slice(0, 12000);
  // Forced tool use: the API returns the score as structured input, so there is no
  // free-text JSON to parse (unescaped quotes inside long reasoning strings broke that).
  const r = await fetch(ANTHROPIC + "/messages", {
    method: "POST", headers: { ...authHeaders(env), "content-type": "application/json" },
    body: JSON.stringify({ model, max_tokens: attempt === 1 ? 6000 : 9000, messages: [{ role: "user", content: prompt }],
      tools: [SCORE_TOOL], tool_choice: { type: "auto" } }),
  });
  if (!r.ok) throw new Error("Anthropic " + r.status + ": " + (await r.text()).slice(0, 300));
  const data = await r.json();
  let j = (data.content || []).find((c) => c.type === "tool_use" && c.name === SCORE_TOOL.name)?.input;
  if (!j) {
    // fallback: tolerant parse of any text block
    const txt = (data.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
    const m = txt.match(/\{[\s\S]*\}/);
    if (!m) { console.error("scoreOne: no tool_use and no JSON for " + block.name, JSON.stringify(data).slice(0, 400)); throw new Error("No structured output (stop_reason " + data.stop_reason + ")"); }
    try { j = JSON.parse(m[0]); }
    catch (e1) {
      try { j = JSON.parse(repairJson(m[0])); }
      catch (e2) { console.error("scoreOne: bad JSON for " + block.name + ": " + e2.message); throw new Error("Model output was not valid JSON: " + e2.message); }
    }
  }
  const incomplete = ["A", "B", "C", "D", "E"].some((k) => typeof j?.factors?.[k]?.score !== "number" || !String(j.factors[k].reason || "").trim());
  if (incomplete) throw new Error("Incomplete structured output (stop_reason " + data.stop_reason + "): factors missing");
  const f = {};
  for (const k of ["A", "B", "C", "D", "E"]) {
    const v = Math.max(0, Math.min(100, Math.round(Number(j.factors?.[k]?.score ?? 0))));
    f[k] = { score: v, reason: String(j.factors?.[k]?.reason || "") };
  }
  const vals = Object.values(f).map((x) => x.score);
  let score = Math.round(vals.reduce((a, b) => a + b, 0) / 5);
  if (Math.min(...vals) <= 30) score = Math.min(score, 65);
  const labels = { A: "Product pull, no sales machine", B: "Fund III financial fit", C: "Operator-transplant readiness", D: "Sector + AI-era durability", E: "Deal shape + exit path" };
  for (const k in f) f[k].label = labels[k];
  const today = new Date().toISOString().slice(0, 10);
  return {
    id: slug(block.name), name: block.name, rank: 0, score, week: block.week || "", hq: j.hq || "",
    state: "pitch", source: "tracker-refresh", addedAt: today, verifiedDate: "", verifiedNote: "",
    factors: f,
    factorReasoning: ["A", "B", "C", "D", "E"].map((k) => k + ": " + f[k].reason).join(" "),
    archetype: j.archetype || "", founderTransition: j.founderTransition || "", checkAbsorbability: j.checkAbsorbability || "",
    what: j.what || "", financials: j.financials || "", aiTailwinds: j.aiTailwinds || "", aiHeadwinds: j.aiHeadwinds || "",
    financialProfile: j.financialProfile || "", sectorFit: j.sector || "", dealDynamics: j.dealDynamics || "",
    read: j.read || "", unverified: Array.isArray(j.unverified) ? j.unverified : [],
  };
}

function calibration(board) {
  const cs = board.companies.slice().sort((a, b) => b.score - a.score);
  const pick = [...cs.slice(0, 12), ...cs.slice(-4)];
  return pick.map((c) => `- ${c.name} = ${c.score} [${["A", "B", "C", "D", "E"].map((k) => c.factors[k].score).join(" ")}]${c.state === "verified" ? " (verified)" : ""}`).join("\n");
}

/* ---------------- tracker parsing ---------------- */
const MARKER = /Financial Profile\s*\/\/\s*Sector Fit\s*\/\/\s*Deal Dynamics/i;
const WEEK = /^\d{1,2}\/\d{1,2}$/;
function splitCompanies(text) {
  const raw = text.split(/\r?\n/);
  const isLink = raw.map((l) => l.startsWith(LINK));
  const lines = raw.map((l) => (l.startsWith(LINK) ? l.slice(LINK.length) : l));
  // strip "(JL)" style tags, "RESURFACING", leading asterisks, and ": TH, CF" style owner initials after a colon
  const clean = (s) => String(s || "").trim().replace(/\(.*?\)/g, "").replace(/\s+RESURFACING\s*$/i, "").replace(/^\*+|\*+$/g, "").replace(/\s*[:\-\u2013]\s*[A-Z]{2,3}(\s*,\s*[A-Z]{2,3})*\s*$/, "").trim();
  const out = [];
  let week = "";
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (WEEK.test(t)) week = t;
    if (!MARKER.test(t)) continue;
    // name: nearest preceding hyperlinked short line (within the last 4 non-empty lines);
    // fallback: the immediately preceding line if it looks like a name (<= 6 words, no sentence punctuation)
    let name = "", j = i - 1, seenNonEmpty = 0, fallback = "";
    while (j >= 0 && seenNonEmpty < 4) {
      const s = lines[j].trim();
      if (s) {
        if (WEEK.test(s)) break;
        if (isLink[j]) { name = clean(s); break; }
        if (seenNonEmpty === 0) fallback = s;
        seenNonEmpty++;
      }
      j--;
    }
    if (!name) {
      const f = clean(fallback);
      if (f && f.split(/\s+/).length <= 6 && !/[.:;!?]$/.test(f) && !/^(we|the|he|she|they|it|oa|note)\b/i.test(f)) name = f;
    }
    if (!name || name.length > 60) continue;
    let k = i + 1, body = [];
    while (k < lines.length) {
      const s = lines[k].trim();
      if (WEEK.test(s)) break;
      if (MARKER.test(s)) { body.pop(); break; }
      body.push(lines[k]); k++;
    }
    out.push({ name, week, text: name + "\n" + body.join("\n").trim() });
  }
  return out;
}
/* Attach a full ISO date to each block from its M/D week heading, inferring the year from
   document order (the tracker runs newest-first or oldest-first; either works). Then keep
   only blocks on/after MIN_WEEK (YYYY-MM-DD). Blocks with no week heading are dropped when a
   cutoff is set, so nothing undated slips through. */
function applyCutoff(blocks, minWeek) {
  if (!minWeek) return blocks;
  const min = new Date(minWeek + "T00:00:00Z"); if (isNaN(min)) return blocks;
  const md = (w) => { const m = /^(\d{1,2})\/(\d{1,2})$/.exec(w || ""); return m ? [+m[1], +m[2]] : null; };
  const dated = blocks.map((b) => ({ b, md: md(b.week) })).filter((x) => x.md);
  if (!dated.length) return [];
  const key = (x) => x.md[0] * 100 + x.md[1];
  const newestFirst = key(dated[0]) >= key(dated[dated.length - 1]);
  // relative year offsets along the document, then anchor the newest heading to this year
  let off = 0, prev = null;
  for (const x of dated) {
    if (prev !== null) { if (newestFirst && key(x) > prev) off -= 1; if (!newestFirst && key(x) < prev) off += 1; }
    prev = key(x); x.off = off;
  }
  const maxOff = Math.max(...dated.map((x) => x.off));
  const thisYear = new Date().getUTCFullYear();
  const out = [];
  for (const x of dated) {
    const d = new Date(Date.UTC(thisYear - (maxOff - x.off), x.md[0] - 1, x.md[1]));
    if (d >= min) out.push({ ...x.b, date: d.toISOString().slice(0, 10) });
  }
  return out;
}
const norm = (s) => String(s || "").toLowerCase().replace(/\(.*?\)/g, "").replace(/[^a-z0-9]+/g, "").trim();
const slug = (s) => String(s || "").toLowerCase().replace(/\(.*?\)/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);

/* ---------------- Google Docs ---------------- */
async function fetchDocText(env) {
  const token = await googleToken(env);
  const r = await fetch(`https://docs.googleapis.com/v1/documents/${env.TRACKER_DOC_ID}?includeTabsContent=true`, { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) throw new Error("Docs API " + r.status + " " + (await r.text()).slice(0, 200));
  const doc = await r.json();
  const parts = [];
  const walkBody = (body) => { for (const el of body?.content || []) parts.push(elText(el)); };
  if (doc.tabs?.length) { const walkTabs = (tabs) => { for (const t of tabs) { walkBody(t.documentTab?.body); if (t.childTabs) walkTabs(t.childTabs); } }; walkTabs(doc.tabs); }
  else walkBody(doc.body);
  return parts.join("");
}
const LINK = "\u0001L\u0001"; // sentinel prefixed to short paragraphs that carry a hyperlink (company names in the tracker are links)
function elText(el) {
  if (el.paragraph) {
    const runs = el.paragraph.elements || [];
    const t = runs.map((e) => e.textRun?.content || "").join("");
    const linked = runs.some((e) => e.textRun?.textStyle?.link && (e.textRun.content || "").trim());
    return linked && t.trim().length <= 80 ? LINK + t : t;
  }
  if (el.table) return (el.table.tableRows || []).map((row) => (row.tableCells || []).map((cell) => (cell.content || []).map(elText).join("")).join(" | ")).join("\n");
  if (el.tableOfContents) return (el.tableOfContents.content || []).map(elText).join("");
  return "";
}
async function googleToken(env) {
  if (env.GOOGLE_OAUTH_REFRESH_TOKEN) {
    const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: env.GOOGLE_OAUTH_CLIENT_ID, client_secret: env.GOOGLE_OAUTH_CLIENT_SECRET, refresh_token: env.GOOGLE_OAUTH_REFRESH_TOKEN, grant_type: "refresh_token" }) });
    const j = await r.json(); if (!j.access_token) throw new Error("OAuth refresh failed: " + JSON.stringify(j).slice(0, 200)); return j.access_token;
  }
  if (env.GOOGLE_SA_KEY) {
    const sa = JSON.parse(env.GOOGLE_SA_KEY);
    const now = Math.floor(Date.now() / 1000);
    const hdr = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    const claim = b64url(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/documents.readonly", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
    const key = await crypto.subtle.importKey("pkcs8", pemToDer(sa.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(hdr + "." + claim));
    const jwt = hdr + "." + claim + "." + b64url(sig);
    const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }) });
    const j = await r.json(); if (!j.access_token) throw new Error("Service-account auth failed: " + JSON.stringify(j).slice(0, 200)); return j.access_token;
  }
  throw new Error("No Google credentials configured (GOOGLE_SA_KEY or GOOGLE_OAUTH_* secrets)");
}
function b64url(x) { const s = typeof x === "string" ? btoa(unescape(encodeURIComponent(x))) : btoa(String.fromCharCode(...new Uint8Array(x))); return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function pemToDer(pem) { const b = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""); const bin = atob(b); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; }

/* ---------------- helpers ---------------- */
let cachedModel = null;
async function pickOpus(env) {
  if (cachedModel) return cachedModel;
  try {
    const r = await fetch(ANTHROPIC + "/models?limit=100", { headers: authHeaders(env) });
    if (r.ok) { const ids = ((await r.json()).data || []).map((m) => m.id);
      for (const want of OPUS_PREFERENCE) { const hit = ids.find((id) => id === want || id.startsWith(want + "-")); if (hit) return (cachedModel = hit); }
      const any = ids.filter((id) => id.includes("opus")).sort().reverse()[0]; if (any) return (cachedModel = any); }
  } catch {}
  return (cachedModel = OPUS_PREFERENCE[0]);
}
function authHeaders(env) {
  const h = { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": API_VERSION };
  if (env.ANTHROPIC_WORKSPACE_ID) h["anthropic-workspace-id"] = env.ANTHROPIC_WORKSPACE_ID; // only needed for org-level keys
  return h;
}
function allowedList(env) { return String(env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim()).filter(Boolean); }
function allowed(origin, env) { const l = allowedList(env); return l.includes("*") || !origin || l.includes(origin); }
function corsHeaders(origin, env) { const l = allowedList(env); const allow = l.includes("*") ? (origin || "*") : (l.includes(origin) ? origin : l[0] || "");
  return { "Access-Control-Allow-Origin": allow, "Access-Control-Allow-Methods": "POST, GET, OPTIONS", "Access-Control-Allow-Headers": "content-type, authorization, x-access-code", "Access-Control-Max-Age": "86400", "Vary": "Origin" }; }
function json(o, status, cors) { return new Response(JSON.stringify(o), { status, headers: { ...cors, "content-type": "application/json" } }); }
function timingSafeEqual(a, b) { if (a.length !== b.length) return false; let out = 0; for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i); return out === 0; }

/* ---------------- scoring prompt ---------------- */
const RUBRIC = `You are scoring a software company for Elsewhere Partners, an Austin growth-equity firm. Score ONLY from the text provided (one section of a deal-team pipeline tracker). Do not invent facts. Where the text is silent, score conservatively and say so in the reasoning. This is a PITCH score: everything in the document is a company or deal-team claim until independently verified, and your "unverified" list must name every material claim.

WHAT ELSEWHERE ACTUALLY BUYS (from their 21-company portfolio): an operating-team transplant business that uses capital as the entry ticket. They buy a time-tested software product (often 7-25 years old) with proven customer pull and a stale or absent go-to-market, install a CEO or Executive Chair from their infrastructure-software bench (SolarWinds, SailPoint, AlienVault alumni), often move HQ to Texas, build a US sales motion, and sell to an upmarket sponsor (Sumeru, Brighton Park, Francisco, Updata) or strategic in 3-5 years at $100-250M. CEO changed in 12 of 21 deals. Sole investor in most deals, labelled "Series A" but control in substance; they buy through lower-middle-market bankers (Cascadia, FirstCapital, Vista Point, GrowthPoint, Lincoln, Capstone). Fund III writes $20-50M majority checks, so the practical ARR floor is about $5M unless a founder secondary is doing the work. Sector results: IT infrastructure/DevOps/monitoring best, then security, then healthcare IT with a bench operator; business applications are their weak vintage. Prior VC is fine when stale and small; live momentum rounds, term sheets, SAFE caps and strategic auctions are disqualifiers. The single strongest signal in their book is product pull without a sales machine.

FACTORS (0-100 each):
A. Product pull without a sales machine: inbound, PLG, open-source, marketplace or channel-driven growth with a tiny or absent sales team; real logos acquired without S&M. 90+ = thousands of customers with zero S&M. 70 = mostly inbound with a small team. 40 = outbound-built or POC-dependent. 20 = founder-led with few customers.
B. Fund III financial fit: $5M+ ARR (or secondary-heavy structure); growth and efficiency together (Rule of 40); recurring quality (GRR first); capital efficiency; EVIDENCE QUALITY: company-stated numbers get a haircut, "anecdotal/TBC" numbers get a haircut hard, contradicted numbers score low. 90 = $10M+ growing 50%+ profitable with named retention. 60 = in-band ARR with a forecast growth claim. 45 = $3-4M below floor but healthy. 30 or below = under $3M, or services counted as ARR, or single customer >25%.
C. Operator-transplant readiness: founder will become CPO/CTO under an installed CEO or accept an OA Executive Chair; explicit transition plans; founders who have exited before; GTM gap an infra/security/MSP bench can fill. 85+ = founders explicitly want to hand over. 60 = founder open to majority. 45 = "prefer to retain control" or silent. 30 = wants capital not a partner.
D. Sector and AI-era durability: infra/DevOps/monitoring > security > healthcare IT with operator > business apps; AI makes the product MORE necessary (proprietary data, identity/data-layer control, agent-era tooling) rather than commoditizing it; consolidating category with active acquirers. 85+ = infra/security asset AI makes more valuable. 60 = home-turf sector with a bundling threat. 40 = platform already ships the feature or LLMs commoditize the core. 25 = both.
E. Deal shape and exit path: bootstrapped or stale VC wanting cleanup; majority available; LMM banker is fine; NA/Europe/Israel HQ willing to build US presence; a NAMEABLE upmarket sponsor or strategic buyer at $100-250M in 3-5 years. 80+ = bootstrapped, no process, nameable buyers. 55 = workable with one friction (geography, minority preference). 30 or below = VC-shaped round (Series A/B minority), strategic auction, external price anchor, founders under 25%, governance vacuum.

Score = average of A-E. Any factor at 30 or below caps the total at 65.

You MUST record your answer by calling the record_score tool (do not answer in prose). Field guidance (same shape as the tool):
{"hq":"","sector":"one line: category and the durability situation","what":"one or two sentences on what the product does, concretely","financials":"the numbers as stated, compact, flagged as stated","factors":{"A":{"score":0,"reason":""},"B":{"score":0,"reason":""},"C":{"score":0,"reason":""},"D":{"score":0,"reason":""},"E":{"score":0,"reason":""}},"archetype":"which Elsewhere archetype it resembles (1 aged product no GTM / 2 founder-led niche leader with overlay / 3 healthcare IT with operator / 4 stale cap-table cleanup / none) and why in one clause","founderTransition":"one sentence on whether the founder will hand over, from the text","checkAbsorbability":"one sentence: can a $20-50M majority check price sanely at this ARR","aiTailwinds":"two or three sentences: what makes this more necessary or valuable in the AI era, and what in the deal shape helps","aiHeadwinds":"two or three sentences: platform bundling, LLM commoditization, capital asymmetry, deal-shape problems","financialProfile":"one line","dealDynamics":"one line","unverified":["each material claim the document makes that is not corroborated inside the document itself, e.g. named logos, growth rates, retention, EBITDA, headcount"],"read":"two sentences: the Elsewhere read and the one question that decides it"}`;
