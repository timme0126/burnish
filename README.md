# 🔥 burnish

**Burn-after-read pastebin with zero-knowledge server.** You paste, you get a link, the first person to open it reads it — and it is gone from the server forever. The server never sees your plaintext or your key.

## How small is it

- `server.js` — ~50 lines, Node ≥ 20, **zero dependencies**, no database.
- `index.html` — the entire client, one file, WebCrypto only.

## Why the promises are real (unlike most pastebins)

| Promise | Mechanism |
|---|---|
| Server can't read your paste | AES-GCM-256, key generated in your browser. The server stores an opaque `base64(iv).base64(ciphertext)` blob. |
| Key doesn't leak to the host | The key travels in the URL **fragment** (`#id.key`), which browsers never send in requests, logs, or `Referer`. |
| Read exactly once | One-time claim via atomic `fs.rename` — under N concurrent readers, exactly one wins (`200`), all others get `410 gone`. Verified by test. |
| Burning is real deletion | Winner reads, then deletes immediately; a sweeper clears crash residue. One file per paste — nothing to reconcile. |
| No cache copies | Every response is `Cache-Control: no-store` — no CDN or browser may keep a copy. |
| No plaintext in logs | Request bodies are never logged. Only ids and status codes are. |
| No memory DoS | Body capped at 256 KB **while streaming** — rejected before buffering completes. |
| No HTML execution | Served paste is decrypted into `textContent` only; CSP is locked to `'self'`; API responses are `text/plain` + `nosniff`. |
| No enumeration | Ids are 128-bit random; a wrong id and an already-burned id return the identical `410`. |

## Run it

```bash
node server.js            # http://127.0.0.1:8787  (PORT= to change)
node test.js              # 11 checks: crypto round-trip, one-time claim, size cap, header posture
```

## Threat model — what this is honest about

**Strong against:** the server operator (no plaintext, no key), re-reads, replay, cache persistence, casual id guessing.

**Known limits (by design, not bugs):**
- The link *is* the secret. Anyone who sees the full URL **including the fragment** (browser history on a shared machine, a pasted-into-chat link preview fetch won't get it — fragments aren't requested) can be the one reader. Share links through a private channel, not screenshots.
- First-claim means a wrong click **destroys** the paste. That is the feature.
- Rate limiting is per-process and per-IP-best-effort: the limiter is a single-process `Map` keyed on the connection — if you put a proxy in front, bind it to the verified client IP at the proxy tier. Brute-forcing 32-hex ids is off the table regardless.
- A malicious client can spam creates (each ≤256 KB). Cap it at your reverse proxy or accept churn; unconsumed files have no TTL by design (they're opaque blobs — add a cron `find store -maxdepth 1 -mmin +60 -delete` if you want one).
- No post-quantum story: if that worries you, this tool's whole point is that the key never leaves the URL — rotate anyway.

**Browser check (manual, 2 min):** open the page, paste anything, copy the link from a *fresh* incognito window — you should see it once, then "already burned."

## Deploy notes

TLS is mandatory (the key-in-fragment trick relies on transport encryption to keep the fragment private between the two browsers). Any reverse proxy works — just forward `POST /paste` and `GET /paste/*` untouched; the app has exactly two endpoints.

## Design lineage

Built after a full security audit of a popular Next.js pastebin where *every* privacy control (password, burn-after-read, deletion, GPS coarsening) was client-side theater. burnish keeps one control — burn-after-read — and makes the server structurally incapable of faking it.
