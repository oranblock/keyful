# Keyful

**An offline encrypted vault for Android. Your key is a printed paper card — nothing is stored on a server, and the app has no internet permission at all.**

Seal any file, message, or secret. To open it you enter cells from your paper card; the app rebuilds a 260-bit key and decrypts locally. No account, no cloud, no telemetry.

> **Status: unaudited, work in progress.** QV5 vaults are single-factor. QV6/QV7 add your voice and optionally a passphrase; they are newer and less tested. Treat it as a serious prototype, not a product. Do not protect anything you cannot afford to lose. See [Security model](#security-model) for exactly what it does and does not protect.

---

## Why it exists

Most vaults keep your key in a cloud account (1Password, Bitwarden) or on a device you can lose. Keyful keeps the key **off the device entirely** — on paper you control — and proves it: the app ships with **no `android.permission.INTERNET`**, so it physically cannot send your data anywhere. Check the manifest yourself.

## How it works

Your secret is a degree-12 polynomial over GF(2^20) — a **260-bit key**. The paper card holds **140 cells**, each a point on that polynomial.

- **Seal:** derive the master key from the card, encrypt the payload with AES-256-GCM (chunked, per-chunk authenticated).
- **Unseal:** the app asks for 15 random cells; **any 13 correct cells** rebuild the exact same key. The extra 2 catch typos before decrypting.
- **Damage tolerance:** any 13 of 140 work, so you can lose or smudge up to 127 cells and still recover.

### Vault types

You choose the type when you seal:

| Type | To open | Notes |
|---|---|---|
| `.qv5` | 15 cells (13 + 2 typo checks) | Card alone. Recoverable with `qvault5.py`. |
| `.qv6` | N cells (3–13, chosen at seal) + your voice | No passphrase. Weak if the card is stolen (see below). |
| `.qv7` | N cells + your voice + a passphrase | Strongest. |

For QV6/QV7:
- The file holds 32 locks. Each lock is built from a different random set of N cells. At unlock, the app asks for the cells of one lock, chosen at random.
- The right cells open that lock. Then you say 5 random words (plus the passphrase for QV7).
- The voice becomes key material through a fuzzy extractor. It is not compared against a stored voiceprint, and no voiceprint is ever stored.
- All factors are needed to derive the key. Details are in [SECURITY.md](SECURITY.md#qv6--qv7-cells--voice--passphrase).

### Crypto

| Piece | Choice |
|---|---|
| Secret sharing | Shamir over GF(2^20), polynomial `x^20 + x^3 + 1` (`0x100009`), threshold K=13 |
| Encryption | AES-256-GCM, chunked, AAD binds header hash + chunk index + last-flag |
| Key derivation | SHAKE-256 |
| P2P handshake | X25519 ECDH + ChaCha20-Poly1305, nonce-bound, 60s TTL, replay-checked |
| Device seal | Argon2id (32 MB, 3 iterations) |
| QV6/QV7 cell locks | 32 random N-cell subsets, Argon2id (8 MiB) + AES-256-GCM |
| QV6/QV7 voice lock | Sample-then-lock fuzzy extractor over a Vosk x-vector (64 locks × 12 bits), Argon2id; passphrase Argon2id (64 MiB, 3 passes) |
| Hardening | `FLAG_SECURE`, `allowBackup=false`, RAM wipe on background + 3-min idle |

## Security model

**Read this before trusting it with anything.**

- **The card is the key.** Any 13 of the 140 cells reconstruct the whole secret. A single photograph of the card is total compromise. Treat it exactly like a crypto seed phrase — never photograph it, never put it in cloud storage.
- **The encryption is strong; the exposure is human.** The 260-bit key is not brute-forceable. The realistic attack is someone seeing your card or watching you type, not breaking the math.
- **QV5 is single factor.** Whoever has 13 cells can open a matching `.qv5`. A card + a vault file = access.
- **QV7 adds two more factors: your voice and a passphrase.** With QV7, a card + a vault file is not enough. The passphrase carries the weight; the voice adds about 12 bits.
- **QV6 is card + voice only.** Someone holding your card and a copy of the file can brute-force the voice part offline in about a minute. A voice is also not a secret: any recording of you works offline. Use QV7 for anything that matters.
- **No voice, no vault.** A QV6/QV7 vault needs your voice and the same speaker model (`vosk-model-spk-0.4`). There is no card-only recovery. Keep a QV5 copy of anything you cannot lose.
- **Offline means offline.** Lose the card and the vault is unrecoverable. That is the design, not a bug.

## Recovery without the app

A vault must outlive the app. The reference Python implementation (`qvault5.py`) decrypts any `.qv5` from the paper card alone — no Android, no server. If a future OS breaks the app, your data is still recoverable with ~1 file and the printed card. This applies to `.qv5` only; `.qv6`/`.qv7` need the app's voice pipeline.

## Build

```
cd android_app
ANDROID_HOME=<sdk> gradle :app:assembleDebug
```

The voice models (~55 MB) are not in the repo. QV6/QV7 and the Voice Lab screen need them; everything else works without them:

```
cd android_app/app/src/main/assets
curl -LO https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip
curl -LO https://alphacephei.com/vosk/models/vosk-model-spk-0.4.zip
unzip vosk-model-small-en-us-0.15.zip && mv vosk-model-small-en-us-0.15 model
unzip vosk-model-spk-0.4.zip && mv vosk-model-spk-0.4 spk
uuidgen > model/uuid && uuidgen > spk/uuid
```

The microphone is used only for QV6/QV7 and the Voice Lab. Speech is processed on the device and is never stored. The app still has no `INTERNET` permission.

Release builds sign from env-provided keystore paths (see `release.env`); keys are never committed. Unit tests: `gradle :app:testDebugUnitTest`.

## What this is not

- Not a password manager (no autofill, no sync — that's the point).
- Not audited. No third-party security review yet.
- Not for custody of other people's money or keys.

## License

MIT — see [LICENSE](LICENSE). Third-party components keep their own licenses (JMRTD/SCUBA are LGPL-3.0).

---

*Built and hardened with the help of Claude Code. The name on the repo is Keyful.*
