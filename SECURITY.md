# Security Policy

Keyful is an **unaudited prototype**. This file says what to attack, what's already known, and how to report. Breakage reports are welcome — that's the point of the repo being public.

## Threat model

**Goal:** a payload sealed on-device stays confidential and tamper-evident, with the key living **off the device** (a printed paper card), and with **no network exfiltration path** (the app has no `INTERNET` permission).

**In scope — please break these:**
- The AES-256-GCM sealing: chunking, and the per-chunk AAD that binds `SHA-256(header) + chunk index + last-flag`. Look for nonce reuse, chunk reorder/truncation, or cross-vault replay.
- The Shamir layer over GF(2^20) (`x^20 + x^3 + 1`, K=13 of 140): does any set of <13 cells leak information? Any reconstruction shortcut?
- The X25519 + ChaCha20-Poly1305 ephemeral handshake: replay, MITM, nonce handling, TTL/clock-skew bypass.
- Argon2id device-seal parameters and the passkey path.
- Key material lifetime in memory: RAM-wipe on background/idle, and any place plaintext or coefficients outlive their use.
- Any accidental data egress (should be impossible with no `INTERNET` permission — prove otherwise).

## Known limitations (not new findings)

Report these only if you can escalate them past what's stated:

- **Single factor.** Whoever holds any **13 correct cells** can open a matching vault. There is currently no required passkey on top. A card photo = total compromise. This is documented and on the roadmap (off-card factor: passkey or device-held share).
- **Offline = unrecoverable if lost.** No cloud recovery, by design.
- **Obfuscation is not encryption.** Anything relying on hiding the *format* (vs. the *key*) is understood to be non-security. Don't report format obfuscation as protection.
- **`detekt` gate** in the release script is currently bypassed. Known.
- **GF(2^20) arithmetic is not constant-time.** `gmul` has data-dependent branches. Given the threat model — 13 cells typed by hand over seconds on an air-gapped device — microarchitectural cache-timing attacks are not considered reachable. Constant-time reimplementation is welcome but low priority for this use.
- **Memory zeroing is best-effort.** Secrets held as `ByteArray` are `fill(0)`-wiped on use and on background/idle, but the JVM/ART garbage collector may relocate objects and immutable `String` copies can linger in the heap. True erasure would require native (`mlock`/`memset_s`) handling. Treat RAM-wipe as defense-in-depth, not a guarantee.
- **Not audited.** No third-party review has been done.

## Mitigations already in place

- **Custom in-app keypad** (`SecureBase32Keypad`) for cell entry, so shares are not typed through a third-party/system keyboard (Gboard sync, malicious IME, most accessibility snoops). Wired into the unlock screen.
- **`FLAG_SECURE`** blocks screenshots, screen recording, and the recents-preview thumbnail of the unlock screen.
- **No `INTERNET` permission** — no network exfiltration path exists.

## What is NOT in scope

- Physical attacks on the paper card (photographing it, shoulder-surfing the unlock) — the card *is* the key; protecting it is the user's job, same as a seed phrase.
- Rooted/compromised-device attacks against an app that is actively unlocked.
- Social engineering.

## How to report

- **Non-sensitive** (design questions, crypto critique, "your AAD is wrong"): open a public GitHub issue. Loud is fine.
- **Sensitive** (a working key-recovery or decryption break): open a GitHub issue titled `security: contact me` **without the exploit details**, and I'll set up a private channel. Do not post a working decryption break publicly until it's discussed.

## Verify it yourself

The reference Python implementation `qvault5.py` decrypts any `.qv5` from the paper card alone — no app, no server. Use it to confirm exactly what a vault does and does not require.

No bounty is offered — this is a prototype. Credit is given for any accepted finding.
