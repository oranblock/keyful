# Keyful

**An offline encrypted vault for Android. Your key is a printed paper card — nothing is stored on a server, and the app has no internet permission at all.**

Seal any file, message, or secret. To open it you enter cells from your paper card; the app rebuilds a 260-bit key and decrypts locally. No account, no cloud, no telemetry.

> **Status: unaudited, single-factor, work in progress.** Treat it as a serious prototype, not a product. Do not protect anything you cannot afford to lose. See [Security model](#security-model) for exactly what it does and does not protect.

---

## Why it exists

Most vaults keep your key in a cloud account (1Password, Bitwarden) or on a device you can lose. Keyful keeps the key **off the device entirely** — on paper you control — and proves it: the app ships with **no `android.permission.INTERNET`**, so it physically cannot send your data anywhere. Check the manifest yourself.

## How it works

Your secret is a degree-12 polynomial over GF(2^20) — a **260-bit key**. The paper card holds **140 cells**, each a point on that polynomial.

- **Seal:** derive the master key from the card, encrypt the payload with AES-256-GCM (chunked, per-chunk authenticated).
- **Unseal:** the app asks for 15 random cells; **any 13 correct cells** rebuild the exact same key. The extra 2 catch typos before decrypting.
- **Damage tolerance:** any 13 of 140 work, so you can lose or smudge up to 127 cells and still recover.

### Crypto

| Piece | Choice |
|---|---|
| Secret sharing | Shamir over GF(2^20), polynomial `x^20 + x^3 + 1` (`0x100009`), threshold K=13 |
| Encryption | AES-256-GCM, chunked, AAD binds header hash + chunk index + last-flag |
| Key derivation | SHAKE-256 |
| P2P handshake | X25519 ECDH + ChaCha20-Poly1305, nonce-bound, 60s TTL, replay-checked |
| Device seal | Argon2id (32 MB, 3 iterations) |
| Hardening | `FLAG_SECURE`, `allowBackup=false`, RAM wipe on background + 3-min idle |

## Security model

**Read this before trusting it with anything.**

- **The card is the key.** Any 13 of the 140 cells reconstruct the whole secret. A single photograph of the card is total compromise. Treat it exactly like a crypto seed phrase — never photograph it, never put it in cloud storage.
- **The encryption is strong; the exposure is human.** The 260-bit key is not brute-forceable. The realistic attack is someone seeing your card or watching you type, not breaking the math.
- **Single factor, today.** Whoever has 13 cells can open a matching vault. There is (currently) no passkey required on top. A card + a vault file = access. A roadmap item is an off-card factor (passkey or device-held share) so the card alone is not enough.
- **Offline means offline.** Lose the card and the vault is unrecoverable. That is the design, not a bug.

## Recovery without the app

A vault must outlive the app. The reference Python implementation (`qvault5.py`) decrypts any `.qv5` from the paper card alone — no Android, no server. If a future OS breaks the app, your data is still recoverable with ~1 file and the printed card.

## Build

```
cd android_app
ANDROID_HOME=<sdk> gradle :app:assembleDebug
```

Release builds sign from env-provided keystore paths (see `release.env`); keys are never committed. Unit tests: `gradle :app:testDebugUnitTest`.

## What this is not

- Not a password manager (no autofill, no sync — that's the point).
- Not audited. No third-party security review yet.
- Not for custody of other people's money or keys.

## License

TBD before any public release.

---

*Built and hardened with the help of Claude Code. The name on the repo is Keyful; the current package id is still `com.qvault.app` pending a rename.*
