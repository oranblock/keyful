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
- **Passport binding** (`nfc/CivilIdChipReader.kt`): PACE/BAC with the passport details, DG15, Active Authentication. Can a copied chip, or a replayed response, pass as the real one?
- **QV6 / QV7 vaults** (`domain/VoiceVault.kt`, `voicelab/VoiceLock.kt`) — see [QV6 / QV7](#qv6--qv7-cells--voice--passphrase) below. Open one without the right cells, voice or passphrase. Relabel, splice or reorder its lock sets. Find a way to get the voice or passphrase check without first having the cell secret.

## Known limitations (not new findings)

Report these only if you can escalate them past what's stated:

- **QV5 is single factor.** Whoever holds any **13 correct cells** can open a matching `.qv5`. A card photo = total compromise. QV7 (below) adds a voice and a passphrase on top of the card.
- **Offline = unrecoverable if lost.** No cloud recovery, by design.
- **Obfuscation is not encryption.** Anything relying on hiding the *format* (vs. the *key*) is understood to be non-security. Don't report format obfuscation as protection.
- **`detekt` gate** in the release script is currently bypassed. Known.
- **GF(2^20) arithmetic is not constant-time.** `gmul` has data-dependent branches. Given the threat model — 13 cells typed by hand over seconds on an air-gapped device — microarchitectural cache-timing attacks are not considered reachable. Constant-time reimplementation is welcome but low priority for this use.
- **Memory zeroing is best-effort.** Secrets held as `ByteArray` are `fill(0)`-wiped on use and on background/idle, but the JVM/ART garbage collector may relocate objects and immutable `String` copies can linger in the heap. True erasure would require native (`mlock`/`memset_s`) handling. Treat RAM-wipe as defense-in-depth, not a guarantee.
- **Not audited.** No third-party review has been done.

## QV6 / QV7 (cells + voice + passphrase)

New and less tested than QV5. When you seal, you choose N cells (3 to 13) and a vault type:

- `.qv6`: N cells + voice.
- `.qv7`: N cells + voice + passphrase.

**Construction:**

```
cellSecret, voiceSecret = 32 random bytes each
passportId  = SHA-256(tag ‖ DG15 public key), only when the vault uses a passport
vaultKey    = SHAKE256("QV67-KEY" ‖ magic ‖ cellSecret ‖ voiceSecret [‖ passportId])
cell lock i = AES-GCM(Argon2id(values of cell subset S_i ‖ i, salt_i, 8 MiB, 1 pass), cellSecret)
              32 locks, each S_i a random N-cell subset of the 140
voice lock  = VoiceLock: sample-then-lock fuzzy extractor (Canetti et al.)
              over a 128-d Vosk x-vector (vosk-model-spk-0.4):
              pool = 64 strongest dims, sign = bit; 64 locks, each over a random 12-dim subset
              lock key = Argon2id(kFactor ‖ bits ‖ j, salt_j, 8 MiB, 1 pass)
              kFactor  = SHA-256(tag ‖ kPass ‖ cellSecret [‖ passportId])
              kPass    = Argon2id(passphrase, 64 MiB, 3 passes), or zeros for QV6
payload     = the QV5 chunked AES-256-GCM container keyed by vaultKey;
              both lock sets sit in its header, which every chunk authenticates
```

**Unlock:**
1. The app picks one cell lock at random and asks for its N cells.
2. The right cells give `cellSecret`.
3. If the vault uses a passport, you tap it. The chip is opened over PACE or BAC with the passport details. It must sign a fresh challenge with its Active Authentication key. Its DG15 key digest gives `passportId`. The header holds a 16-bit check of `passportId` that catches a wrong passport at the tap.
4. You say 5 random words from a 24-word list. Speech recognition must hear the exact word, and 3 misses bring new words.
5. The whole answer becomes the voiceprint.
6. The voiceprint, the passphrase and the passport must open one voice lock.

Every factor is key material. The voiceprint is never stored.

**Known limitations. These are design facts, not findings:**

- **Voice is low entropy.** Each voice lock hides 12 bits. With the right cells and passphrase, a random other voice opens one of the 64 locks about L/2^K = 64/4096 ≈ 1.6% of the time. Similar voices do better.
- **QV6 plus a stolen card is weak.** Take someone who holds the paper card and a copy of the `.qv6` file. The cells give them `cellSecret`, so only 4096 voice guesses per lock remain. That is roughly a minute on a PC. QV7's passphrase is what holds in this case.
- **A voice is not a secret.** Anyone with a recording of you can compute your x-vector offline, from any speech. The random words only stop replay through the app's own microphone path. They do nothing against an attacker who has the file and the cells.
- **No voice, no vault.** A lasting change in your voice makes a QV6/QV7 vault unopenable, and so does a different speaker model. QV6/QV7 have no card-only recovery. `qvault5.py` cannot open them. Keep a QV5 copy of anything you cannot lose.
- **Shoulder-surfing the cells** reveals the cell set of one lock. Such an attacker still needs the voice, plus the passphrase for QV7.
- **The file shows which 64 of the 128 voiceprint dimensions are strongest.** It does not show their signs.
- **The passport factor is a public key, not a secret.** Its digest is key material, so an attacker who has never read your chip cannot open the vault. But anyone who has held your passport, with its printed details, can read DG15 and compute `passportId` offline. Active Authentication proves the real chip is present, but that check runs in the app, and an offline attacker skips the app. The 16-bit check in the header also weakly links a vault to a list of known passports.
- **Kuwait Civil IDs cannot bind.** Their applets refuse any reader without PACI keys (6982), and their ISO 14443-B PUPI changes on every tap. The values that stay stable are identical on every card. The app therefore asks for a passport.

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

The reference Python implementation `qvault5.py` decrypts any `.qv5` from the paper card alone — no app, no server. Use it to confirm exactly what a vault does and does not require. It does not open `.qv6`/`.qv7`, which need the app's voice pipeline. Their construction is covered by `VoiceVaultTest` and `VoiceLockTest`.

No bounty is offered — this is a prototype. Credit is given for any accepted finding.
