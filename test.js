const B = "http://127.0.0.1:8787";
const enc = new TextEncoder();
const b64e = a => Buffer.from(a).toString("base64");
const b64d = s => new Uint8Array(Buffer.from(s, "base64"));
let fails = 0;
const ck = (name, cond, extra="") => { console.log(cond ? "PASS" : "FAIL", name, extra); if(!cond) fails++; };
(async () => {
  const rawKey = await crypto.subtle.exportKey("raw", await crypto.subtle.generateKey({name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({name:"AES-GCM",iv}, key, enc.encode("top secret: launch codes 🚀"));
  const blob = b64e(iv) + "." + b64e(ct);
  let r = await fetch(B+"/paste", {method:"POST", body: blob});
  const id = await r.text();
  ck("create returns 201 + 32-hex id", r.status===201 && /^[0-9a-f]{32}$/.test(id), id);

  // server must hold only ciphertext (blob contains no plaintext)
  const fs = require("fs");
  const stored = fs.readFileSync("store/"+id, "utf8");
  ck("stored bytes contain no plaintext", !stored.includes("launch") && stored === blob);

  const rs = await Promise.all([1,2,3,4,5].map(() => fetch(`${B}/paste/${id}`)));
  const st = await Promise.all(rs.map(x=>x.status));
  ck("exactly one of 5 concurrent reads wins", st.filter(s=>s===200).length === 1, st.join(","));
  await new Promise(res=>setTimeout(res,50));
  const body = await rs.find(x=>x.status===200).text();
  const [ivs, cts] = body.split(".");
  const k2 = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const pt = new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:b64d(ivs)}, k2, b64d(cts)));
  ck("round-trip decrypt", pt === "top secret: launch codes 🚀", pt);
  ck("re-read after burn = 410", (await fetch(`${B}/paste/${id}`)).status === 410);
  ck("store dir empty after burn (zero residue)", fs.readdirSync("store").filter(f=>!f.startsWith(".")).length === 0);
  try {
    r = await fetch(B+"/paste", {method:"POST", body:"A".repeat(400*1024)});
    ck("oversize body rejected 413", r.status === 413);
  } catch (e) { // early 413 + socket teardown can surface as a reset; either outcome proves the cap
    ck("oversize body rejected (connection cut by 413)", /ECONNRESET|socket|terminated/i.test(String(e.cause || e)));
  }
  ck("traversal blocked", (await fetch(B+"/paste/..%2f..%2fetc%2fpasswd")).status !== 200);
  ck("unknown id = 410 (no existence oracle for random ids)", (await fetch(B+"/paste/00000000000000000000000000000000")).status === 410);
  ck("garbage payload rejected", (await fetch(B+"/paste", {method:"POST", body:"<script>alert(1)</script>"})).status === 400);
  r = await fetch(B+"/paste", {method:"POST", body: blob});
  ck("cache-control no-store on API", r.headers.get("cache-control") === "no-store");
  console.log(fails ? `--- ${fails} FAILURES` : "--- ALL PASS");
  process.exit(fails?1:0);
})();
