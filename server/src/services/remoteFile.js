/**
 * Fetch a file from a user-supplied link, safely (SSRF protection):
 * only http/https, private/local addresses blocked (checked at connect time),
 * max 3 redirects, 10 s timeout, 10 MB limit.
 */
const http = require("http");
const https = require("https");
const dns = require("dns");
const net = require("net");
const path = require("path");
const cfg = require("../config");

const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 10000;

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const l = ip.toLowerCase();
  if (l === "::1" || l === "::" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80")) return true;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(l);
  return m ? isPrivateIp(m[1]) : false;
}

// Validates the address the socket will ACTUALLY connect to (defeats DNS rebinding)
function safeLookup(hostname, options, cb) {
  if (typeof options === "function") { cb = options; options = {}; }
  dns.lookup(hostname, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!cfg.allowPrivateUrls && addrs.some((a) => isPrivateIp(a.address)))
      return cb(new Error("That link points to a private or local address, which is not allowed"));
    if (options && options.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}

function filenameFrom(headers, url) {
  const cd = headers["content-disposition"] || "";
  let m = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (m) { try { return decodeURIComponent(m[1]); } catch (_) { /* fall through */ } }
  m = /filename="?([^";]+)"?/i.exec(cd);
  if (m) return m[1];
  try {
    const base = path.basename(decodeURIComponent(url.pathname));
    if (base && base !== "/") return base;
  } catch (_) { /* ignore */ }
  return "download";
}

function fetchRemote(urlStr, hops = 0) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch { return reject(new Error("That is not a valid link")); }
    if (!["http:", "https:"].includes(u.protocol)) return reject(new Error("Only http and https links are allowed"));
    if (u.username || u.password) return reject(new Error("Links with embedded credentials are not allowed"));
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(host) && !cfg.allowPrivateUrls && isPrivateIp(host))
      return reject(new Error("That link points to a private or local address, which is not allowed"));

    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, { method: "GET", lookup: safeLookup, timeout: TIMEOUT_MS, headers: { "User-Agent": "VouchFetcher/1.0", Accept: "*/*" } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (hops >= MAX_REDIRECTS) return reject(new Error("Too many redirects"));
        let next;
        try { next = new URL(res.headers.location, u).toString(); } catch { return reject(new Error("Bad redirect from remote server")); }
        return resolve(fetchRemote(next, hops + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`Remote server answered ${res.statusCode}`)); }
      if (Number(res.headers["content-length"]) > cfg.maxFileBytes) { res.destroy(); return reject(new Error("Linked file is larger than 10 MB")); }
      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > cfg.maxFileBytes) { req.destroy(); reject(new Error("Linked file is larger than 10 MB")); }
        else chunks.push(c);
      });
      res.on("end", () => resolve({ buffer: Buffer.concat(chunks), mimeType: (res.headers["content-type"] || "").split(";")[0] || undefined, filename: filenameFrom(res.headers, u) }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("Remote server timed out")));
    req.on("error", reject);
    req.end();
  });
}

module.exports = { fetchRemote, isPrivateIp };
