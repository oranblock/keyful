# QVault 5 Mobile — Technical Specification

## 1. System Overview
QVault 5 Mobile is a Modern Android Development (MAD) application designed to secure sensitive files and keys using an offline physical paper card and polynomial secret sharing over $\text{GF}(2^{20})$.

## 2. Architecture & Tech Stack
- **Platform**: Android (Min SDK 26, Target SDK 35)
- **Language**: Kotlin 2.0+ (100% Pure Kotlin, Zero XML)
- **UI Framework**: Jetpack Compose + Material 3
- **State Management**: StateFlow + ViewModel (Clean MVVM)
- **Crypto Engine**:
  - Finite field arithmetic over $\text{GF}(2^{20})$ with polynomial $x^{20} + x^3 + 1$ ($0x100009$).
  - Lagrange polynomial interpolation for threshold recovery ($K=13$).
  - AES-256-GCM authenticated encryption (javax.crypto / BouncyCastle). Keys are derived
    from the paper card at unlock time and held only in RAM; the app does **not** use the
    Android Keystore, and no key is ever persisted to disk.
  - SHAKE-256 master-key derivation; SHAKE-256 fingerprints.

> **Trust model note.** Security rests entirely on the paper card plus the passkey.
> Any $K=13$ of the 140 cells reconstruct the whole secret, so the printed card must be
> treated like a seed phrase — a single photograph is full compromise. Earlier builds
> claimed a per-device "Civil ID hardware token"; that claim was false (the value was a
> constant shared by every card of the same product) and has been removed.

## 3. UI/UX Features
- **Dynamic 15-Cell Challenge**: Prompts 15 coordinates chosen randomly from $\binom{140}{13} \approx 1.2 \times 10^{17}$ combinations.
- **Auto-Advancing Input Grid**: 15 custom text fields with auto-focus movement upon entering 4 base32 characters.
- **Instant Consistency Checking**: Reed-Solomon style error detection using the 2 check cells to immediately detect typos.
- **Card Slip Visualizer**: Interactive paper slip explorer showing Slips 1–10 (14 cells each) and fingerprints.
