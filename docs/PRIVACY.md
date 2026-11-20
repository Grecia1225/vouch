# Privacy: what each viewer can see

Principle: a third party needs to answer one question, "is this document registered, and does my copy match?". Everything else stays hidden unless the owner chooses to reveal it (progressive disclosure, data minimisation).

## Who sees what
| Field | Owner (logged in) | Third party, **Basic** link | **+ file name** | **+ technical** | Anyone reading the blockchain |
|---|---|---|---|---|---|
| Registered / date / version / network | yes | yes | yes | yes | date and block yes |
| File name | yes | no | yes | yes | no (never on-chain) |
| SHA-256 fingerprint | yes | no | no | yes | **yes (public by nature)** |
| Transaction hash, block | yes | no | no | yes | yes |
| Uploader / owner identity | yes | no | no | no | no (see below) |
| Document metadata, author, software | yes | no | no | no | no |
| Location and capture details | yes | no | no | no | no |
| Hidden-content findings | yes | no | no | no | no |
| Version history | yes | version number only | same | same | hash links yes |
| The document itself | yes (download) | no | no | no | no |

A viewer's "check my copy" answer is only MATCHES / DIFFERENT VERSION / DOES NOT MATCH. It never contains a hash.

## Controls in the product
- **Capability links.** The certificate QR holds `/v/<token>`: 144 random bits, not the hash. The owner picks the level, an expiry (7/30/90 days or never), can issue a new link (the old one stops working) or revoke it. Unknown, expired and revoked links give the same "not valid" answer, so nothing is revealed about which.
- **Public certificate PDF.** A separate variant with no fingerprint, transaction, owner or location.
- **Unlinkable on-chain reference.** The contract stores `HMAC(secret, user : document hash)` instead of a user id. Two documents from the same user cannot be linked by reading the chain, yet the server can still prove who registered what. (Records created before this change keep the old reference.)
- **Metadata and location are opt-in and never public.** The stored snapshot drops GPS coordinates; decoded hidden payloads are not stored.

## Honest limits
1. **The hash on the blockchain is public and permanent.** Hiding it in the web page does not hide it from the chain.
2. **Dictionary attack.** Anyone can test a guess against a public hash. For a document that is mostly predictable (a form with few variable fields, a short standard letter), an attacker can enumerate candidates and confirm which one was registered. Large or unique documents are safe in practice. Mitigation today: include something unique and unguessable in documents that are mostly boilerplate.
3. **A hash may count as personal data** if it can be linked to a person, which complicates erasure on an append-only chain. The EDPB's 2025 blockchain guidelines discuss this (cited in an earlier research summary; check the text before quoting it) and India's DPDP Act 2023 may apply. Take legal advice before claiming compliance.
4. **Timing and volume are public.** Anyone can see that something was registered at a given time.

## Recommended next step: salted commitments (not built yet)
Store `SHA-256(fileHash || salt)` on-chain instead of the bare hash, with a random per-document salt kept by the owner and the server. Dictionary attacks then fail, and the chain reveals nothing about the content.
Cost: independent verification needs the salt, which the owner shares together with the file when they choose to. "Not registered" can no longer be shown from the chain alone. It is a good fit for an opt-in "private mode". Merkle batching and zero-knowledge proofs are heavier alternatives.
