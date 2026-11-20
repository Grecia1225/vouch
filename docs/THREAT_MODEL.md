# Vouch Threat Model

Method: STRIDE per component, with trust boundaries (see `diagrams/trust-boundaries.png`). Status values are honest: **Mitigated** (control exists in code and is tested or testable), **Partial**, or **Accepted** (known prototype limitation).

## 1. What we protect (assets)
| Asset | Why it matters |
|---|---|
| A1. Integrity of the proof (hash, time, version link) | The whole point of the product |
| A2. Confidentiality of uploaded documents | Contracts and ID proofs are sensitive |
| A3. User accounts and sessions | Access to one's documents and certificates |
| A4. Relayer private key | Sole writer to the contract; pays gas |
| A5. Privacy of location and author metadata | Can identify people |
| A6. Server availability and audit trail | Accountability and uptime |

## 2. Actors
- **Honest user** and **verifier** (a third party checking a certificate).
- **Malicious user:** uploads hostile files or links, tries to tamper, forge or guess passwords.
- **Outsider / network attacker:** observes or alters traffic, scans the API.
- **Malicious or compromised operator:** has database or server access.
- **Chain-level attacker:** attempts to rewrite or hide blockchain history (infeasible on a healthy public chain; see residual risks for testnets).

## 3. Trust boundaries
- **TB1** Browser/device/internet to the Vouch API: everything crossing it is untrusted input.
- **TB2** Vouch API to the blockchain: only the relayer wallet can write.
- **TB3** Anyone to the blockchain (read): requires no trust in Vouch. This is what the *Independent check* page and CLI use.

## 4. Threats and controls
| ID | STRIDE | Threat | Control in the project | Status |
|---|---|---|---|---|
| T1 | Tampering | Document altered after registration | SHA-256 fingerprint on-chain; any change gives a different hash (measured: 100% of about 10,000 modified files detected, see `measurements/`). TAMPERED verdict when the certificate's expected hash is supplied | Mitigated |
| T2 | Tampering | Operator edits the database to change a record | The authoritative record is on the blockchain, not MongoDB. Independent check reads only the chain | Mitigated |
| T3 | Tampering | Version history rewritten or reordered | `notarizeVersion` requires the previous hash to exist already; versions only link backwards, so no cycles or reordering. Contract tests cover this | Mitigated |
| T4 | Repudiation | Operator denies or alters what happened | Hash-chained audit log: editing, deleting or reordering an event breaks every later hash (tested). `verify-audit.js --anchor` writes the head hash on-chain | Mitigated (anchor is manual) |
| T5 | Spoofing | Password guessing, credential stuffing | bcrypt hashing, rate limiting on `/api/auth`, account lockout after 5 failures for 15 minutes, uniform error and dummy hash comparison so unknown emails look the same | Partial (no MFA, no email verification) |
| T6 | Spoofing | Stolen token reused | JWT expires in 7 days; helmet headers | Partial. Token lives in localStorage, so an XSS bug would expose it. No refresh or revocation |
| T7 | Info disclosure | One user reads another's documents | Every document route filters by `owner`; certificates and downloads require login. Verification endpoints return no filenames or owner details | Mitigated |
| T8 | Info disclosure | Files exposed at rest or in transit | HTTPS in deployment guide; files not on-chain | Partial. GridFS files are not encrypted at rest (Accepted for prototype; mitigation: encrypted volume or client-side encryption) |
| T9 | Info disclosure | Location/author metadata leaks | Location is opt-in; stored snapshot drops GPS coordinates; public verify returns no metadata; analyse endpoint stores nothing | Mitigated |
| T10 | Info disclosure | Server-side request forgery through the "Link" input | http/https only, no credentials in URL, private/loopback/link-local ranges blocked **at connect time** (defeats DNS rebinding), 3 redirects max, 10 s timeout, 10 MB cap. Tested against localhost, 169.254.169.254 and `file://` | Mitigated |
| T11 | DoS | Oversized or malicious uploads | 10 MB limit, max 10 items, max 5 links, zip entries size-capped before inflate, in-memory analysis only | Partial. Regex-based PDF parsing on 10 MB inputs could be slow; rate limits reduce abuse |
| T12 | DoS | API flooding | Rate limits on auth, verify, metadata | Partial (no global limit, no WAF) |
| T13 | Elevation | Hostile file executes on the server | Files are never executed or rendered server-side; PDFs and Office files are only parsed as bytes | Mitigated |
| T14 | Tampering | Client lies about time or location | Block timestamp comes from the chain, never the browser. Location and capture time are labelled "reported by browser (unverified)" everywhere | Mitigated (by honesty, not prevention) |
| T15 | Elevation | Relayer key stolen | Key only in server environment, never sent to clients; contract allows only this key to write; `transferOwnership` exists for rotation | Partial. Single key is a single point of failure. Future: multisig owner, secrets manager |
| T16 | Spoofing | Operator registers hashes of documents never uploaded, or refuses to register | Cannot backdate (chain time). Cannot silently drop: users keep certificates. Refusal is an availability issue | Accepted |
| T17 | Tampering | Attacker swaps a certificate's QR to point elsewhere | Certificate prints the full hash; verifier re-hashes the file regardless of the QR; independent check ignores Vouch URLs entirely | Mitigated |
| T18 | Info disclosure | Test key leaked | `.env.example` uses Hardhat's public test key for local use only, with a warning; `.gitignore` excludes `.env` | Mitigated (user must not reuse it) |
| T19 | Tampering | Supply-chain attack through npm packages | Few direct dependencies; zero-dependency verifier | Partial. Add lockfiles, `npm audit`, Dependabot |
| T20 | Repudiation | Reorg or reset of a test network erases records | Hardhat local chain resets on restart (documented). Amoy is a public testnet and can be reset or deprecated | Accepted for testnet. Production should use mainnet or a permissioned chain with governance |
| T21 | Info disclosure | A user's records are linked together by reading the public chain | On-chain reference is now `HMAC(secret, user:hash)`, different for every document. Tested | Mitigated (new records) |
| T22 | Info disclosure | Third party learns more than needed from a verification result | Share links reveal only date/version by default; file name and technical details need explicit owner consent; uploader, metadata, location and hidden-content findings are never public. Tested at every level | Mitigated |
| T23 | Spoofing | Share link guessed, leaked or kept after it should stop | 144-bit random token, expiry, revoke and regenerate; identical response for unknown, expired and revoked links; rate limit on `/api/p` | Partial (anyone holding a live link can use it) |
| T24 | Info disclosure | Dictionary attack on a low-entropy document's public hash | Documented; adding unique content helps. Salted commitments are the planned fix (see `PRIVACY.md`) | Accepted for now |
| T25 | Tampering | Hidden payload extraction misused, or an extracted payload executed | Extraction needs login, is rate limited and audited, returns an inert `.dat` attachment with `nosniff` and `sandbox` headers; nothing is executed or rendered server-side | Mitigated |
| T26 | Elevation | Optional ExifTool/c2patool runs on hostile files | Disabled by default; no shell, fixed arguments, random private temp file, 10 s timeout, 2 MB output cap, minimal environment. Production should add a no-network container | Partial (opt-in) |
| T27 | DoS / Tampering | Malicious files abuse the parsers (zip bombs, huge images, regex blow-up) | Size limits at every parser, zip entries capped before inflate, pixel cap on LSB analysis, 10 MB upload limit, in-memory only | Partial |

## 5. What Vouch deliberately does NOT claim
- It does **not** prove who authored a document, that its content is true, or that signing was voluntary.
- It is **not** a statutory notarial act. In India, electronic records still need the evidence certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023, and a JWT login is not a licensed digital signature. Obtain legal review before presenting it as legally conclusive.
- Metadata findings are indicators: metadata can be edited or removed.
- A registered hash proves the exact bytes existed no later than the recorded block time. That is all.

## 6. Residual risks and the roadmap
1. MFA and email verification (T5, T6).
2. Encryption at rest and optional client-side encryption (T8).
3. Multisig or HSM-held contract owner (T15).
4. Automatic daily anchoring of the audit head hash (T4).
5. Dependency scanning in CI (T19).
6. Production chain choice with a governance story (T20).

## 7. How to test these claims yourself
- `npm test` runs the contract tests (versions, access control) and the server tests (SSRF blocking, audit-chain tamper detection, lockout, verifier decoding, metadata and steganography detection against real fixtures, privacy redaction rules).
- `node server/scripts/measure-hash.js` reproduces the tamper-detection measurements.
- `node verifier/verify.mjs <file> --rpc <url> --contract <addr>` checks a file with no Vouch server.
