// Автоматичний підпис оновлень КОРН-БОТ (GitHub Actions).
// inbox/*.kin — архів збірки, зашифрований ключем скриньки (RSA-OAEP-3072 + AES-256-GCM); прочитати може лише цей робочий процес.
// Робочий процес: розшифрувати → перевірити архів (files.json, обовʼязкові файли, шляхи, версія новіша за поточну) →
//   зашифрувати ключем доставки (AES-256-GCM) → підписати маніфест ключем розробника (ECDSA P-256) →
//   korn-update.json + KORN-BOT_v<версія>.kpkg у корінь, старі .kpkg і оброблений .kin прибрати.
// Ключі — лише в секретах репозиторію: KORN_SIGN_KEY, KORN_DELIVERY_KEY, KORN_INBOX_KEY. У журнал вони не потрапляють.
"use strict";
const fs = require("fs"), path = require("path"), crypto = require("crypto"), zlib = require("zlib");
const FORMAT = "korn-update/1";
const need = (k) => { const v = (process.env[k] || "").trim(); if (!v) throw new Error(`секрет ${k} не задано`); return v; };
const b64 = (s) => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
const signKey = crypto.createPrivateKey({ key: b64(need("KORN_SIGN_KEY")), format: "der", type: "pkcs8" });
const delivery = b64(need("KORN_DELIVERY_KEY"));
const inboxKey = crypto.createPrivateKey({ key: b64(need("KORN_INBOX_KEY")), format: "der", type: "pkcs8" });
if (delivery.length !== 32) throw new Error("KORN_DELIVERY_KEY має бути 32 байти (base64)");
const pubDer = crypto.createPublicKey(signKey).export({ format: "der", type: "spki" });
const fp = crypto.createHash("sha256").update(pubDer).digest("hex").toUpperCase().slice(0, 16).match(/.{4}/g).join("-");

function parseVer(v) { const m = String(v || "").match(/^(\d+)\.(\d+)\.(\d+)/); return m ? [+m[1], +m[2], +m[3]] : [0, 0, 0]; }
function newer(a, b) { const x = parseVer(a), y = parseVer(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i]; return false; }
function zipEntries(buf) {
  let e = buf.length - 22; while (e >= 0 && buf.readUInt32LE(e) !== 0x06054b50) e--;
  if (e < 0) throw new Error("це не zip-архів");
  const n = buf.readUInt16LE(e + 10); let off = buf.readUInt32LE(e + 16); const out = [];
  for (let i = 0; i < n && buf.readUInt32LE(off) === 0x02014b50; i++) {
    const method = buf.readUInt16LE(off + 10), csize = buf.readUInt32LE(off + 20), ln = buf.readUInt16LE(off + 28), ex = buf.readUInt16LE(off + 30), cm = buf.readUInt16LE(off + 32), lho = buf.readUInt32LE(off + 42);
    out.push({ name: buf.toString("utf8", off + 46, off + 46 + ln), method, csize, lho }); off += 46 + ln + ex + cm;
  }
  return out;
}
function zipRead(buf, list, name) {
  const en = list.find((x) => x.name === name); if (!en) return null;
  const start = en.lho + 30 + buf.readUInt16LE(en.lho + 26) + buf.readUInt16LE(en.lho + 28);
  const data = buf.subarray(start, start + en.csize);
  return en.method === 0 ? Buffer.from(data) : zlib.inflateRawSync(data);
}
function openInbox(file) {
  const b = fs.readFileSync(file);
  if (b.subarray(0, 5).toString() !== "KIN1\n") throw new Error(`${file}: не файл скриньки`);
  const wl = b.readUInt16BE(5), wrapped = b.subarray(7, 7 + wl), iv = b.subarray(7 + wl, 19 + wl), body = b.subarray(19 + wl, b.length - 16), tag = b.subarray(b.length - 16);
  const k = crypto.privateDecrypt({ key: inboxKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, wrapped);
  const d = crypto.createDecipheriv("aes-256-gcm", k, iv); d.setAAD(Buffer.from("KIN1\n")); d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}
const root = process.cwd();
const inbox = fs.existsSync("inbox") ? fs.readdirSync("inbox").filter((f) => f.endsWith(".kin")).sort() : [];
if (!inbox.length) { console.log("у скриньці нічого немає"); process.exit(0); }
let cur = null; try { cur = JSON.parse(fs.readFileSync("korn-update.json", "utf8")); } catch {}
const report = [];
for (const f of inbox) {
  const fileIn = path.join("inbox", f);
  try {
    const zip = openInbox(fileIn);
    const list = zipEntries(zip), names = list.map((x) => x.name);
    const fj = JSON.parse(zipRead(zip, list, "files.json").toString("utf8"));
    const version = String(fj.version || "");
    if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error("у files.json немає версії");
    for (const n of ["bot.js", "webui.js", "START_BOT.bat", "update.js"]) if (!names.includes(n)) throw new Error(`в архіві немає ${n}`);
    const bad = names.find((n) => /(^|[\\/])\.\.([\\/]|$)/.test(n) || /^([\\/]|[A-Za-z]:)/.test(n) || /^(bot_data|node_modules)([\\/]|$)/i.test(n));
    if (bad) throw new Error(`шлях поза програмою бота: ${bad}`);
    if (cur && !newer(version, cur.version)) throw new Error(`версія ${version} не новіша за опубліковану ${cur.version}`);
    const readme = (zipRead(zip, list, "README.txt") || Buffer.alloc(0)).toString("utf8").replace(/^﻿/, "");
    const i = readme.indexOf(`ЩО НОВОГО У ${version}`), j = i >= 0 ? readme.indexOf("\n=====", i) : -1;
    const notes = i >= 0 ? readme.slice(i, j > 0 ? j : i + 1800).trim().slice(0, 1800) : "";
    const made = new Date().toISOString();
    const head = Buffer.from(JSON.stringify({ format: FORMAT, version, notes, made }));
    const hl = Buffer.alloc(4); hl.writeUInt32BE(head.length);
    const MAGIC = Buffer.from("KPKG1\n"), iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", delivery, iv); c.setAAD(MAGIC);
    const ct = Buffer.concat([c.update(Buffer.concat([hl, head, zip])), c.final(), c.getAuthTag()]);
    const pkg = Buffer.concat([MAGIC, iv, ct]);
    const file = `KORN-BOT_v${version}.kpkg`;
    const m = { format: FORMAT, version, file, size: pkg.length, sha256: crypto.createHash("sha256").update(pkg).digest("hex"), made };
    const text = [m.format, m.version, m.file, String(m.size), m.sha256, m.made].join("\n");
    m.sig = crypto.sign("sha256", Buffer.from(text), { key: signKey, dsaEncoding: "ieee-p1363" }).toString("base64");
    m.key = fp;
    for (const old of fs.readdirSync(root).filter((x) => x.endsWith(".kpkg"))) fs.unlinkSync(old);
    fs.writeFileSync(file, pkg);
    fs.writeFileSync("korn-update.json", JSON.stringify(m, null, 1) + "\n");
    cur = m;
    report.push(`✓ ${version}: ${file} (${pkg.length} Б, sha256 ${m.sha256.slice(0, 12)}…), підписано ключем ${fp}`);
  } catch (e) {
    report.push(`✕ ${f}: ${e.message}`);
  }
  fs.unlinkSync(fileIn);
}
fs.writeFileSync("last-release.txt", `${new Date().toISOString()}\n${report.join("\n")}\n`);
console.log(report.join("\n"));
