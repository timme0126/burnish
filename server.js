// burnish — burn-after-read pastebin. Server never sees plaintext or the key.
// Node >= 20, zero dependencies. Atomic one-time claim via fs.rename.
const http = require("node:http"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const STORE = path.join(__dirname, "store"), USED = path.join(STORE, ".consumed"), PORT = process.env.PORT || 8787;
const MAX_BODY = 256 * 1024; // 256 KB of ciphertext, enforced while streaming
fs.mkdirSync(USED, { recursive: true });

const readBody = (req) => new Promise((res, rej) => {
  let len = 0, chunks = [];
  req.on("data", c => { len += c.length; if (len > MAX_BODY) { rej({ code: 413 }); req.destroy(); } else chunks.push(c); });
  req.on("end", () => res(Buffer.concat(chunks)));
});
const send = (res, code, body = "", type = "text/plain") =>
  res.writeHead(code, { "Content-Type": type, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" }).end(body);

http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, "http://x");
    if (req.method === "POST" && u.pathname === "/paste") {
      const body = (await readBody(req)).toString("utf8").trim();
      if (!/^[\w+/=.]{1,350000}$/.test(body)) return send(res, 400, "bad payload");
      const id = crypto.randomBytes(16).toString("hex"); // 128-bit unguessable id
      fs.writeFileSync(path.join(STORE, id), body, { flag: "wx" }); // EEXIST on impossible collision
      return send(res, 201, id);
    }
    const m = u.pathname.match(/^\/paste\/([0-9a-f]{32})$/);
    if (m && req.method === "GET") {
      const src = path.join(STORE, m[1]), dst = path.join(USED, m[1]);
      try { fs.renameSync(src, dst); } catch { return send(res, 410, "gone"); } // atomic claim: exactly one wins
      const data = fs.readFileSync(dst, "utf8");
      fs.rmSync(dst, { force: true });                    // burn now; sweeper only cleans crash residue
      return send(res, 200, data);
    }
    if (req.method === "GET") {
      const f = { "/": "index.html" }[u.pathname];
      if (!f) return send(res, 404, "not found");
      return send(res, 200, fs.readFileSync(path.join(__dirname, f), "utf8"), "text/html; charset=utf-8");
    }
    send(res, 405, "method");
  } catch (e) { send(res, e.code || 500, e.code ? "too large" : "error"); }
}).listen(PORT, () => {
  console.log(`burnish on :${PORT} — plaintext is nobody's business but yours`);
  setInterval(() => { for (const f of fs.readdirSync(USED)) fs.rmSync(path.join(USED, f), { force: true }); }, 60_000).unref();
});
