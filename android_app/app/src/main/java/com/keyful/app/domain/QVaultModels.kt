package com.keyful.app.domain

data class CellCoordinate(
    val slip: Int,
    val cell: Int
) {
    val label: String get() = "s${slip} c${cell}"
}

data class ChallengeItem(
    val coord: CellCoordinate,
    var value: String = "",
    val isValid: Boolean = false
)

data class VaultCard(
    val cells: Map<Pair<Int, Int>, String>,
    val coef: List<Int>,
    val fingerprint: String,
    val keyFingerprint: String
)

sealed interface UnlockState {
    object Idle : UnlockState
    object Verifying : UnlockState
    data class Success(
        val masterKeyFp: String,
        val metaType: String,
        val metaName: String?,
        val payload: ByteArray
    ) : UnlockState {
        fun wipe() {
            payload.fill(0.toByte())
        }
    }
    /** QV6/QV7 with passport: the cells opened their lock; the passport tap comes next. */
    object NeedPassport : UnlockState
    /** QV6/QV7: the cells (and passport) opened their locks; the voice (+ passphrase for QV7) comes next. */
    data class NeedVoice(val withPass: Boolean) : UnlockState
    data class TypoDetected(val badIndices: List<Int>, val message: String) : UnlockState
    data class Error(val message: String) : UnlockState
}

sealed interface SealState {
    object Idle : SealState
    object Sealing : SealState
    data class Success(val fileName: String, val size: Int, val message: String) : SealState
    data class Error(val message: String) : SealState
}

sealed interface NfcScanUiState {
    object Idle : NfcScanUiState
    data class WaitingForCard(val action: NfcAction, val message: String) : NfcScanUiState
    data class Processing(val message: String) : NfcScanUiState
    data class Success(val message: String) : NfcScanUiState
    data class Error(val error: String) : NfcScanUiState
}

enum class NfcAction {
    SEAL_CARD,
    UNSEAL_VAULT,
    SIGN_CHALLENGE,
    RESTORE_CARD_TO_RAM,
    SEAL_VAULT_PAYLOAD,
    /** QV6/QV7: read the passport chip id as a key factor of the vault being sealed or opened. */
    VAULT_PASSPORT
}

