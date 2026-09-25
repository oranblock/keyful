package com.keyful.app.ui

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.keyful.app.domain.*
import com.keyful.app.nfc.CivilIdChipReader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets

class QVaultViewModel : ViewModel() {

    companion object {
        private const val TAG = "QVault"
        private const val MAX_VOICE_TRIES = 3
    }

    private val _card = MutableStateFlow<VaultCard?>(null)
    val card: StateFlow<VaultCard?> = _card.asStateFlow()

    /**
     * Card credentials and passkey for the next tap.
     *
     * The chip cannot be opened without the details printed on the card, and the vault
     * must not be unlockable by the card alone, so both are collected before scanning
     * and dropped afterwards.
     */
    data class CardCredentials(
        val accessKey: CivilIdChipReader.AccessKey,
        val passkey: ByteArray
    )

    private val _hasCredentials = MutableStateFlow(false)
    val hasCredentials: StateFlow<Boolean> = _hasCredentials.asStateFlow()

    private var cardCredentials: CardCredentials? = null

    fun setCardCredentials(accessKey: CivilIdChipReader.AccessKey, passkey: ByteArray) {
        cardCredentials = CardCredentials(accessKey, passkey)
        _hasCredentials.value = true
    }

    fun clearCardCredentials() {
        cardCredentials?.passkey?.fill(0)
        cardCredentials = null
        _hasCredentials.value = false
    }

    private val _challenge = MutableStateFlow<List<ChallengeItem>>(emptyList())
    val challenge: StateFlow<List<ChallengeItem>> = _challenge.asStateFlow()

    private val _unlockState = MutableStateFlow<UnlockState>(UnlockState.Idle)
    val unlockState: StateFlow<UnlockState> = _unlockState.asStateFlow()

    private val _sealState = MutableStateFlow<SealState>(SealState.Idle)
    val sealState: StateFlow<SealState> = _sealState.asStateFlow()

    private val _activeVaultBytes = MutableStateFlow<ByteArray?>(null)
    val activeVaultBytes: StateFlow<ByteArray?> = _activeVaultBytes.asStateFlow()

    private val _activeVaultName = MutableStateFlow<String?>(null)
    val activeVaultName: StateFlow<String?> = _activeVaultName.asStateFlow()

    private val _loadedVaultCardFp = MutableStateFlow<String?>(null)
    val loadedVaultCardFp: StateFlow<String?> = _loadedVaultCardFp.asStateFlow()

    // --- Civil ID NFC & Device Bound Hardware Storage ---
    private val _sealedCardFp = MutableStateFlow<String?>(null)
    val sealedCardFp: StateFlow<String?> = _sealedCardFp.asStateFlow()

    private val _nfcScanState = MutableStateFlow<NfcScanUiState>(NfcScanUiState.Idle)
    val nfcScanState: StateFlow<NfcScanUiState> = _nfcScanState.asStateFlow()

    // --- Wireless / Ephemeral Handshake (Zero-Typing) ---
    private val _activeChallengeQr = MutableStateFlow<String?>(null)
    val activeChallengeQr: StateFlow<String?> = _activeChallengeQr.asStateFlow()

    private val _generatedResponseQr = MutableStateFlow<String?>(null)
    val generatedResponseQr: StateFlow<String?> = _generatedResponseQr.asStateFlow()

    private var activeVerifierPriv: X25519PrivateKeyParameters? = null
    private var activeChallengeEnvelope: EphemeralHandshakeEngine.ChallengeEnvelope? = null
    private var pendingChallengeToSign: String? = null

    data class PendingSealPayload(
        val bytes: ByteArray,
        val metaType: String,
        val metaName: String?,
        val destFolder: File?,
        val outputStream: java.io.OutputStream?
    )
    private var pendingSealPayload: PendingSealPayload? = null

    // --- QV6 / QV7: a few paper-card cells + voice (+ passphrase) ---
    private val _vaultFormat = MutableStateFlow(QVaultEngine.MAGIC)
    val vaultFormat: StateFlow<String> = _vaultFormat.asStateFlow()

    private var voiceVault: VoiceVault.Parsed? = null
    private var voiceVaultLock = 0
    private var cellSecret: ByteArray? = null
    private var voiceFails = 0
    private val rng = java.security.SecureRandom()

    data class VoiceSealRequest(
        val bytes: ByteArray,
        val metaType: String,
        val metaName: String?,
        val format: String,
        val cells: Int,
        val toSaf: Boolean,
        val burn: Boolean
    ) {
        val fileName: String
            get() = (if (metaType == "text") "secret_message" else metaName ?: "file") + "." + format.lowercase()
    }

    private val _voiceSealRequest = MutableStateFlow<VoiceSealRequest?>(null)
    val voiceSealRequest: StateFlow<VoiceSealRequest?> = _voiceSealRequest.asStateFlow()

    // Sealed QV6/QV7 bytes waiting for the SAF picker; the name asks the UI to open it.
    private var voiceExport: Pair<VoiceSealRequest, ByteArray>? = null
    private val _voiceExportName = MutableStateFlow<String?>(null)
    val voiceExportName: StateFlow<String?> = _voiceExportName.asStateFlow()

    init {
        newChallenge()
    }

    fun generateNewCard() {
        viewModelScope.launch {
            val (cells, coef) = QVaultEngine.makeCard()
            val cFp = QVaultEngine.cardFp(cells)
            val mk = QVaultEngine.masterKey(coef)
            val kFp = QVaultEngine.keyFp(mk)
            Log.i(TAG, "Generated fresh in-memory card: CardFP=$cFp")
            _card.value = VaultCard(cells, coef, cFp, kFp)
            newChallenge()
        }
    }

    fun newChallenge(avoidSlips: Set<Int> = emptySet()) {
        wipeCellSecret()
        val vv = voiceVault
        if (vv != null) {
            // QV6/QV7: the challenge is the cell set of one random cell lock in the file.
            voiceVaultLock = rng.nextInt(vv.cellLocks.size)
            _challenge.value = VoiceVault.challenge(vv, voiceVaultLock).map { ChallengeItem(CellCoordinate(it.first, it.second)) }
            _unlockState.value = UnlockState.Idle
            Log.d(TAG, "Generated fresh ${vv.cells}-cell ${vv.magic} challenge")
            return
        }
        val pairs = QVaultEngine.freshChallenge(avoidSlips)
        _challenge.value = pairs.map { ChallengeItem(CellCoordinate(it.first, it.second)) }
        _unlockState.value = UnlockState.Idle
        Log.d(TAG, "Generated fresh 15-cell challenge")
    }

    fun setLoadedVault(name: String, bytes: ByteArray) {
        if (bytes.isEmpty()) {
            _activeVaultName.value = null
            _activeVaultBytes.value = null
            _loadedVaultCardFp.value = null
            if (voiceVault != null) {
                loadVoiceVault(null)
                newChallenge()
            }
            _unlockState.value = UnlockState.Error("'$name' is empty (0 bytes). A previous export did not finish. Delete this file and seal again.")
            Log.w(TAG, "Rejected empty vault file '$name'")
            return
        }
        _activeVaultName.value = name
        _activeVaultBytes.value = bytes
        try {
            val nl = bytes.indexOf('\n'.code.toByte())
            if (nl > 0) {
                val hdr = JSONObject(String(bytes.copyOfRange(0, nl), StandardCharsets.UTF_8))
                val cFp = if (hdr.has("card")) hdr.getString("card") else null
                _loadedVaultCardFp.value = cFp
                Log.i(TAG, "Loaded vault: '$name' (${bytes.size} bytes), Sealed with Card: $cFp")
            } else {
                _loadedVaultCardFp.value = null
                Log.w(TAG, "Loaded file '$name' has no newline header")
            }
        } catch (e: Exception) {
            _loadedVaultCardFp.value = null
            Log.e(TAG, "Error parsing loaded vault header")
        }
        val damaged = loadVoiceVault(bytes)
        newChallenge()
        damaged?.let { _unlockState.value = UnlockState.Error(it) }
    }

    /** Parses a QV6/QV7 file (none for QV5). Returns an error message if it is damaged. */
    private fun loadVoiceVault(bytes: ByteArray?): String? {
        wipeCellSecret()
        voiceVault = null
        var damaged: String? = null
        if (bytes != null) {
            try {
                voiceVault = VoiceVault.parse(bytes)
            } catch (e: Exception) {
                damaged = "This vault's voice header is damaged: ${e.message}"
                Log.e(TAG, "Damaged QV6/QV7 header: ${e.message}")
            }
        }
        _vaultFormat.value = voiceVault?.magic ?: QVaultEngine.MAGIC
        return damaged
    }

    fun clearLoadedVault() {
        Log.i(TAG, "Cleared loaded vault")
        _activeVaultName.value = null
        _activeVaultBytes.value = null
        _loadedVaultCardFp.value = null
        _unlockState.value = UnlockState.Idle
        if (voiceVault != null) {
            loadVoiceVault(null)
            newChallenge()
        }
    }

    fun clearDecryptedPayload() {
        val current = _unlockState.value
        if (current is UnlockState.Success) {
            Log.i(TAG, "Purging decrypted plaintext from memory (app backgrounded/paused/locked)")
            current.wipe()
            _unlockState.value = UnlockState.Idle
        }
    }

    fun wipeMemory() {
        Log.i(TAG, "Wiping active card, challenge cells, and vaults from memory")
        val current = _unlockState.value
        if (current is UnlockState.Success) {
            current.wipe()
        }
        _activeVaultBytes.value?.fill(0.toByte())
        _card.value = null
        _activeVaultName.value = null
        _activeVaultBytes.value = null
        _loadedVaultCardFp.value = null
        loadVoiceVault(null)
        _voiceSealRequest.value = null
        voiceExport = null
        _voiceExportName.value = null
        _unlockState.value = UnlockState.Idle
        _challenge.value = emptyList()
    }

    fun triggerUnseal() {
        val items = _challenge.value
        val missing = items.mapIndexedNotNull { index, it ->
            if (it.value.length < QVaultEngine.CELL_LEN || !it.isValid) (index + 1) else null
        }
        if (missing.isNotEmpty()) {
            val msg = "Missing ${missing.size} cell(s): ${missing.joinToString(", ") { "#$it" }}. Please enter all ${items.size} cells."
            Log.w(TAG, "triggerUnseal rejected: ${missing.size} cells missing")
            _unlockState.value = UnlockState.Error(msg)
            return
        }
        Log.i(TAG, "triggerUnseal accepted: all ${items.size} cells present")
        checkAutoVerify()
    }

    fun updateCellValue(index: Int, rawValue: String) {
        val current = _challenge.value.toMutableList()
        if (index in current.indices) {
            val cleaned = QVaultEngine.clean(rawValue).take(QVaultEngine.CELL_LEN)
            val validChars = cleaned.all { it in QVaultEngine.B32 }
            current[index] = current[index].copy(
                value = cleaned,
                isValid = cleaned.length == QVaultEngine.CELL_LEN && validChars
            )
            _challenge.value = current
            val filled = current.count { it.value.length == 4 && it.isValid }
            Log.d(TAG, "Cell #${index + 1} updated ($filled/${current.size} filled)")
            checkAutoVerify()
        }
    }

    private fun checkAutoVerify() {
        val items = _challenge.value
        val allFilled = items.all { it.value.length == QVaultEngine.CELL_LEN && it.isValid }
        if (!allFilled) {
            return
        }
        voiceVault?.let { verifyVoiceVaultCells(it, items); return }

        viewModelScope.launch {
            _unlockState.value = UnlockState.Verifying
            Log.i(TAG, "checkAutoVerify: verifying 15 cells in GF(2^20)...")
            try {
                val coords = items.map { Pair(it.coord.slip, it.coord.cell) }
                val vals = items.associate { Pair(it.coord.slip, it.coord.cell) to it.value }

                // Reconstruct polynomial from K cells
                val use = coords.take(QVaultEngine.K)
                val pts = use.associate { QVaultEngine.cellX(it.first, it.second) to QVaultEngine.decCell(vals[it] ?: "") }
                val coef = QVaultEngine.interpolate(pts)

                // Check against remaining check cells
                val bad = coords.drop(QVaultEngine.K).filter { k ->
                    val expectedY = QVaultEngine.evaluate(coef, QVaultEngine.cellX(k.first, k.second))
                    val actualY = QVaultEngine.decCell(vals[k] ?: "")
                    expectedY != actualY
                }

                if (bad.isEmpty()) {
                    val mk = QVaultEngine.masterKey(coef)
                    val keyFingerprint = QVaultEngine.keyFp(mk)
                    Log.i(TAG, "Polynomial verified successfully (KeyFP=$keyFingerprint)")

                    val vault = _activeVaultBytes.value
                    if (vault != null) {
                        try {
                            Log.i(TAG, "Decrypting vault payload (${vault.size} bytes)...")
                            val (meta, payload) = withContext(Dispatchers.Default) {
                                QVaultEngine.openPayload(vault, mk)
                            }
                            val metaType = meta.optString("type", "file")
                            val metaName = if (meta.isNull("name")) null else meta.optString("name")
                            Log.i(TAG, "Vault decrypted successfully (type: $metaType, size: ${payload.size} bytes)")
                            _unlockState.value = UnlockState.Success(
                                masterKeyFp = keyFingerprint,
                                metaType = metaType,
                                metaName = metaName,
                                payload = payload
                            )
                        } catch (e: Exception) {
                            Log.e(TAG, "Decryption failed: wrong key or damaged file")
                            _unlockState.value = UnlockState.Error("Decryption failed: wrong key or damaged file (${e.message})")
                        }
                    } else {
                        // Key verify without vault
                        Log.i(TAG, "Card key verified without vault (KeyFP=$keyFingerprint)")
                        _unlockState.value = UnlockState.Success(
                            masterKeyFp = keyFingerprint,
                            metaType = "text",
                            metaName = null,
                            payload = "Card key verified: $keyFingerprint. No vault loaded.".toByteArray(StandardCharsets.UTF_8)
                        )
                    }
                } else {
                    Log.w(TAG, "Typo detected: ${bad.size} check cells inconsistent")
                    _unlockState.value = UnlockState.TypoDetected(
                        badIndices = listOf(13, 14),
                        message = "Typo detected: entered cells are inconsistent. Please verify typed characters."
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Verification error: ${e.message}")
                _unlockState.value = UnlockState.Error("Verification error: ${e.message}")
            }
        }
    }

    private fun wipeCellSecret() {
        cellSecret?.fill(0)
        cellSecret = null
        voiceFails = 0
    }

    /** QV6/QV7 step 1: the typed cells must open the cell lock this challenge came from. */
    private fun verifyVoiceVaultCells(vv: VoiceVault.Parsed, items: List<ChallengeItem>) {
        val lock = voiceVaultLock
        val typed = items.map { it.value }
        viewModelScope.launch {
            _unlockState.value = UnlockState.Verifying
            val secret = withContext(Dispatchers.Default) { VoiceVault.openCells(vv, lock, typed) }
            if (voiceVault !== vv || voiceVaultLock != lock) {
                secret?.fill(0)   // vault or challenge changed while deriving
                return@launch
            }
            if (secret == null) {
                Log.w(TAG, "${vv.magic}: typed cells did not open their lock")
                _unlockState.value = UnlockState.TypoDetected(
                    badIndices = emptyList(),
                    message = "These ${items.size} cells don't open this vault. Check each one against your paper card."
                )
            } else {
                wipeCellSecret()
                cellSecret = secret
                Log.i(TAG, "${vv.magic}: cells opened their lock, voice next")
                _unlockState.value = UnlockState.NeedVoice(withPass = vv.withPass)
            }
        }
    }

    /**
     * QV6/QV7 step 2: voice (+ passphrase). true = finished, and unlockState says how
     * (opened, damaged, or given up after MAX_VOICE_TRIES); false = the lock stayed shut.
     */
    suspend fun openVoiceVault(voice: FloatArray, pass: CharArray): Boolean {
        val vv = voiceVault
        val cs = cellSecret
        val vault = _activeVaultBytes.value
        if (vv == null || cs == null || vault == null) {
            cancelVoiceUnlock("The voice step expired. Type the cells again.")
            return true
        }
        val opened = try {
            withContext(Dispatchers.Default) { VoiceVault.open(vault, vv, cs, voice, pass) }
        } catch (e: Exception) {
            Log.e(TAG, "${vv.magic}: payload did not decrypt")
            cancelVoiceUnlock("Decryption failed: the vault file is damaged (${e.message})")
            return true
        }
        if (opened == null) {
            voiceFails++
            Log.w(TAG, "${vv.magic}: voice lock stayed shut ($voiceFails/$MAX_VOICE_TRIES)")
            if (voiceFails >= MAX_VOICE_TRIES) {
                cancelVoiceUnlock("The voice lock stayed shut $MAX_VOICE_TRIES times. Type the new cells to try again.")
                return true
            }
            return false
        }
        wipeCellSecret()
        _unlockState.value = UnlockState.Success(
            masterKeyFp = opened.keyFp,
            metaType = opened.meta.optString("type", "file"),
            metaName = if (opened.meta.isNull("name")) null else opened.meta.optString("name"),
            payload = opened.payload
        )
        Log.i(TAG, "${vv.magic} vault opened with cells + voice${if (vv.withPass) " + passphrase" else ""}")
        return true
    }

    /** Leaves the voice step: forgets the cell secret and asks for fresh cells. */
    fun cancelVoiceUnlock(reason: String? = null) {
        if (reason == null && _unlockState.value !is UnlockState.NeedVoice) return
        newChallenge()
        reason?.let { _unlockState.value = UnlockState.Error(it) }
    }

    /** QV6/QV7 seal: the UI shows the voice step while this request is set. */
    fun requestVoiceSeal(
        bytes: ByteArray, metaType: String, metaName: String?,
        format: String, cells: Int, toSaf: Boolean, burn: Boolean
    ) {
        if (_card.value == null) {
            _sealState.value = SealState.Error("No card in memory. Generate or restore a card, then seal again.")
            return
        }
        _voiceSealRequest.value = VoiceSealRequest(bytes, metaType, metaName, format, cells, toSaf, burn)
    }

    fun endVoiceSeal() {
        _voiceSealRequest.value = null
        // Closed mid-derivation (app left): nothing was written.
        if (_sealState.value is SealState.Sealing) _sealState.value = SealState.Idle
    }

    /** Voice (+ passphrase) step of a seal. true = sealed: saved, or waiting for the SAF picker. */
    suspend fun sealWithVoice(voice: FloatArray, pass: CharArray, vaultsDir: File): Boolean {
        val req = _voiceSealRequest.value ?: return false
        val currentCard = _card.value ?: return false
        _sealState.value = SealState.Sealing
        val sealed = try {
            withContext(Dispatchers.Default) {
                VoiceVault.seal(req.bytes, req.metaType, req.metaName, currentCard, req.format, req.cells, voice, pass)
            }
        } catch (e: Exception) {
            _sealState.value = SealState.Error("Sealing failed: ${e.message}")
            throw e
        }
        if (req.toSaf) {
            voiceExport = Pair(req, sealed)
            _voiceExportName.value = req.fileName
        } else {
            val outFile = File(vaultsDir, req.fileName)
            withContext(Dispatchers.IO) {
                if (!vaultsDir.exists()) vaultsDir.mkdirs()
                outFile.writeBytes(sealed)
            }
            finishVoiceSeal(req, outFile.absolutePath, sealed.size)
        }
        return true
    }

    /** The SAF picker is on screen; don't open it again on recomposition. */
    fun voiceExportLaunched() {
        _voiceExportName.value = null
    }

    fun writeVoiceExport(outputStream: java.io.OutputStream) {
        val (req, sealed) = voiceExport ?: run { closeQuietly(outputStream); return }
        voiceExport = null
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { outputStream.use { it.write(sealed) } }
                finishVoiceSeal(req, "Exported via SAF (${req.fileName})", sealed.size)
            } catch (e: Exception) {
                closeQuietly(outputStream)
                _sealState.value = SealState.Error("Export failed: ${e.message}")
            }
        }
    }

    fun cancelVoiceExport() {
        voiceExport = null
        _voiceExportName.value = null
        _sealState.value = SealState.Error("Export cancelled: no file was written.")
    }

    private fun finishVoiceSeal(req: VoiceSealRequest, where: String, size: Int) {
        if (req.burn) burnCard()
        val factors = "${req.cells} cells + voice" + if (req.format == VoiceVault.QV7) " + passphrase" else ""
        _sealState.value = SealState.Success(
            fileName = where,
            size = size,
            message = "${req.format} vault sealed ($factors)" + if (req.burn) ". Card burned from memory." else ""
        )
        Log.i(TAG, "${req.format} vault sealed: $factors")
    }

    fun burnCard() {
        Log.i(TAG, "Burning paper card from memory: paper is the single source of truth")
        _card.value = null
    }

    fun sealText(text: String, destFolder: File, burnAfterSeal: Boolean = false) {
        val currentCard = _card.value ?: return
        if (text.isBlank()) return

        viewModelScope.launch {
            _sealState.value = SealState.Sealing
            try {
                val mk = QVaultEngine.masterKey(currentCard.coef)
                val bytes = text.toByteArray(StandardCharsets.UTF_8)
                val sealed = withContext(Dispatchers.Default) {
                    QVaultEngine.sealPayload(bytes, "text", null, mk, currentCard.fingerprint)
                }

                if (!destFolder.exists()) destFolder.mkdirs()
                val outFile = File(destFolder, "secret_message.qv5")
                outFile.writeBytes(sealed)

                if (burnAfterSeal) {
                    burnCard()
                }

                _sealState.value = SealState.Success(
                    fileName = outFile.absolutePath,
                    size = sealed.size,
                    message = if (burnAfterSeal) {
                        "Message sealed to app vault and card burned from memory!"
                    } else {
                        "Message sealed to app vault: ${outFile.name}"
                    }
                )
            } catch (e: Exception) {
                _sealState.value = SealState.Error("Sealing failed: ${e.message}")
            }
        }
    }

    private fun closeQuietly(stream: java.io.OutputStream?) {
        try {
            stream?.close()
        } catch (_: Exception) {
        }
    }

    fun sealTextToStream(text: String, outputStream: java.io.OutputStream, burnAfterSeal: Boolean = false) {
        val currentCard = _card.value
        if (currentCard == null) {
            closeQuietly(outputStream)
            _sealState.value = SealState.Error("No card in memory, so the exported file is empty. Generate or restore a card, then export again.")
            return
        }
        if (text.isBlank()) {
            closeQuietly(outputStream)
            _sealState.value = SealState.Error("Nothing to seal, so the exported file is empty.")
            return
        }

        viewModelScope.launch {
            _sealState.value = SealState.Sealing
            try {
                val mk = QVaultEngine.masterKey(currentCard.coef)
                val bytes = text.toByteArray(StandardCharsets.UTF_8)
                val sealed = withContext(Dispatchers.Default) {
                    QVaultEngine.sealPayload(bytes, "text", null, mk, currentCard.fingerprint)
                }
                withContext(Dispatchers.IO) {
                    outputStream.use { it.write(sealed) }
                }

                if (burnAfterSeal) {
                    burnCard()
                }

                _sealState.value = SealState.Success(
                    fileName = "Exported via SAF",
                    size = sealed.size,
                    message = if (burnAfterSeal) {
                        "Vault exported via SAF and card burned from memory!"
                    } else {
                        "Vault exported via SAF successfully"
                    }
                )
            } catch (e: Exception) {
                closeQuietly(outputStream)
                _sealState.value = SealState.Error("Sealing failed: ${e.message}")
            }
        }
    }

    fun sealFile(fileBytes: ByteArray, origName: String, destFolder: File, burnAfterSeal: Boolean = false) {
        val currentCard = _card.value ?: return

        viewModelScope.launch {
            _sealState.value = SealState.Sealing
            try {
                val mk = QVaultEngine.masterKey(currentCard.coef)
                val sealed = withContext(Dispatchers.Default) {
                    QVaultEngine.sealPayload(fileBytes, "file", origName, mk, currentCard.fingerprint)
                }

                if (!destFolder.exists()) destFolder.mkdirs()
                val outFile = File(destFolder, "${origName}.qv5")
                outFile.writeBytes(sealed)

                if (burnAfterSeal) {
                    burnCard()
                }

                _sealState.value = SealState.Success(
                    fileName = outFile.absolutePath,
                    size = sealed.size,
                    message = if (burnAfterSeal) {
                        "File sealed to app vault and card burned from memory!"
                    } else {
                        "File sealed to app vault: ${outFile.name}"
                    }
                )
            } catch (e: Exception) {
                _sealState.value = SealState.Error("Sealing failed: ${e.message}")
            }
        }
    }

    fun sealFileToStream(fileBytes: ByteArray, origName: String, outputStream: java.io.OutputStream, burnAfterSeal: Boolean = false) {
        val currentCard = _card.value
        if (currentCard == null) {
            closeQuietly(outputStream)
            _sealState.value = SealState.Error("No card in memory, so the exported file is empty. Generate or restore a card, then export again.")
            return
        }

        viewModelScope.launch {
            _sealState.value = SealState.Sealing
            try {
                val mk = QVaultEngine.masterKey(currentCard.coef)
                val sealed = withContext(Dispatchers.Default) {
                    QVaultEngine.sealPayload(fileBytes, "file", origName, mk, currentCard.fingerprint)
                }
                withContext(Dispatchers.IO) {
                    outputStream.use { it.write(sealed) }
                }

                if (burnAfterSeal) {
                    burnCard()
                }

                _sealState.value = SealState.Success(
                    fileName = "Exported via SAF ($origName.qv5)",
                    size = sealed.size,
                    message = if (burnAfterSeal) {
                        "File vault exported via SAF and card burned from memory!"
                    } else {
                        "File vault exported via SAF successfully"
                    }
                )
            } catch (e: Exception) {
                closeQuietly(outputStream)
                _sealState.value = SealState.Error("Sealing failed: ${e.message}")
            }
        }
    }

    fun saveRecoveredFile(payload: ByteArray, fileName: String, destFolder: File): String {
        if (!destFolder.exists()) destFolder.mkdirs()
        var target = File(destFolder, fileName)
        if (target.exists()) {
            target = File(destFolder, "${fileName}.recovered")
        }
        target.writeBytes(payload)
        return target.absolutePath
    }

    fun saveRecoveredToStream(payload: ByteArray, outputStream: java.io.OutputStream) {
        outputStream.use { it.write(payload) }
    }

    // A copy of the decrypted payload kept alive only for an in-flight SAF export.
    // The SAF "create document" picker backgrounds the app, which triggers
    // clearDecryptedPayload() and wipes unlockState — so the export must read this
    // holder, not the live state, or it writes 0 bytes. Zeroed immediately after write.
    private var pendingExportPayload: ByteArray? = null

    /** Snapshot the current decrypted payload before opening the SAF picker. */
    fun beginRecoveredExport(): Boolean {
        val current = _unlockState.value
        if (current is UnlockState.Success && current.payload.isNotEmpty()) {
            pendingExportPayload = current.payload.copyOf()
            return true
        }
        return false
    }

    /** Write the snapshotted payload to the SAF stream, then zero and drop it. */
    fun writePendingExport(outputStream: java.io.OutputStream): Boolean {
        val payload = pendingExportPayload
        if (payload == null || payload.isEmpty()) {
            try { outputStream.close() } catch (_: Exception) {}
            return false
        }
        return try {
            outputStream.use { it.write(payload) }
            true
        } catch (e: Exception) {
            Log.e(TAG, "Recovered export failed: ${e.message}")
            false
        } finally {
            payload.fill(0)
            pendingExportPayload = null
        }
    }

    fun cancelRecoveredExport() {
        pendingExportPayload?.fill(0)
        pendingExportPayload = null
    }

    // --- Civil ID NFC Hardware Sealing & Unsealing ---

    fun checkSealedCard(filesDir: File) {
        viewModelScope.launch {
            val file = File(filesDir, "sealed_card.qvseal")
            if (file.exists()) {
                try {
                    val container = EphemeralHandshakeEngine.SealedCardContainer.parse(file.readText())
                    _sealedCardFp.value = container.cardFp
                    Log.i(TAG, "Hardware bound sealed card found on device: CardFP=${container.cardFp}")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse sealed card container: ${e.message}")
                    _sealedCardFp.value = null
                }
            } else {
                _sealedCardFp.value = null
            }
        }
    }

    fun deleteSealedCard(filesDir: File) {
        viewModelScope.launch {
            val file = File(filesDir, "sealed_card.qvseal")
            if (file.exists()) file.delete()
            _sealedCardFp.value = null
            Log.i(TAG, "Hardware bound sealed card deleted from device")
        }
    }

    fun restoreCardToRam() {
        startNfcScan(NfcAction.RESTORE_CARD_TO_RAM)
    }

    fun sealWithCivilId(
        payload: ByteArray,
        metaType: String,
        metaName: String?,
        destFolder: File?,
        outputStream: java.io.OutputStream? = null
    ) {
        pendingSealPayload = PendingSealPayload(payload, metaType, metaName, destFolder, outputStream)
        startNfcScan(NfcAction.SEAL_VAULT_PAYLOAD)
    }

    fun startNfcScan(action: NfcAction, challengeStr: String? = null) {
        pendingChallengeToSign = challengeStr
        val msg = when (action) {
            NfcAction.SEAL_CARD -> "Hold Government Civil ID (Saudi / Kuwait / UAE / National ID) to the back of the phone to bind and seal this card."
            NfcAction.UNSEAL_VAULT -> "Hold Government Civil ID to the back of the phone to unseal the active vault instantly."
            NfcAction.SIGN_CHALLENGE -> "Hold Government Civil ID to sign the wireless handshake challenge."
            NfcAction.RESTORE_CARD_TO_RAM -> "Hold Government Civil ID to the back of the phone to restore your card to memory."
            NfcAction.SEAL_VAULT_PAYLOAD -> "Hold Government Civil ID to the back of the phone to encrypt and seal this vault."
        }
        _nfcScanState.value = NfcScanUiState.WaitingForCard(action, msg)
        Log.i(TAG, "NFC Reader Mode activated for action: $action")
    }

    fun cancelNfcScan() {
        _nfcScanState.value = NfcScanUiState.Idle
        clearCardCredentials()
        pendingChallengeToSign = null
        pendingSealPayload?.outputStream?.let {
            closeQuietly(it)
            _sealState.value = SealState.Error("Export cancelled before the Civil ID was tapped, so the exported file is empty. Delete it and export again.")
        }
        pendingSealPayload = null
    }

    /**
     * Opens the captured chip with the credentials the user entered, then continues with
     * the pending seal or unseal using the chip's Active Authentication identity.
     */
    fun handleTagCaptured(tag: android.nfc.Tag, filesDir: File, deviceUuid: String) {
        val credentials = cardCredentials
        if (credentials == null) {
            reportNfcError("Enter your card details before scanning.")
            return
        }

        viewModelScope.launch {
            _nfcScanState.value = NfcScanUiState.Processing("Opening the chip with PACE...")
            val identity = try {
                withContext(Dispatchers.IO) {
                    CivilIdChipReader.read(tag, credentials.accessKey)
                }
            } catch (e: CivilIdChipReader.ChipReadException) {
                Log.e(TAG, "Chip read failed", e)
                reportNfcError(e.message ?: "The card could not be read.")
                return@launch
            } catch (e: Exception) {
                Log.e(TAG, "Chip read failed", e)
                reportNfcError("The card could not be read: ${e.message}")
                return@launch
            }

            if (!identity.activeAuthVerified) {
                Log.e(TAG, "Active Authentication failed for this chip")
                reportNfcError(
                    "This chip did not prove it holds its own private key, so it cannot be trusted. " +
                        "It may be a copy rather than the genuine card."
                )
                return@launch
            }

            Log.i(
                TAG,
                "Chip opened via ${identity.protocol}, Active Authentication verified"
            )
            handleNfcCardDetected(identity.chipId, filesDir, deviceUuid, credentials.passkey)
            clearCardCredentials()
        }
    }

    fun reportNfcError(error: String) {
        _nfcScanState.value = NfcScanUiState.Error(error)
        pendingSealPayload?.outputStream?.let {
            closeQuietly(it)
            _sealState.value = SealState.Error("Civil ID was not read, so the exported file is empty. Delete it and export again.")
            pendingSealPayload = null
        }
    }

    fun handleNfcCardDetected(
        cardUid: ByteArray,
        filesDir: File,
        deviceUuid: String,
        passkey: ByteArray
    ) {
        val state = _nfcScanState.value
        val effectiveAction: NfcAction? = when (state) {
            is NfcScanUiState.WaitingForCard -> state.action
            else -> {
                if (pendingSealPayload != null) {
                    NfcAction.SEAL_VAULT_PAYLOAD
                } else if (_activeVaultBytes.value != null && _sealedCardFp.value != null) {
                    NfcAction.UNSEAL_VAULT
                } else if (_card.value != null && _sealedCardFp.value == null) {
                    NfcAction.SEAL_CARD
                } else if (pendingChallengeToSign != null) {
                    NfcAction.SIGN_CHALLENGE
                } else {
                    null
                }
            }
        }

        if (effectiveAction == null) {
            val hex = cardUid.joinToString(":") { "%02X".format(it) }
            _nfcScanState.value = NfcScanUiState.Success("Civil ID Chip Detected ($hex)\nLoad a vault to unseal, or generate a card to seal.")
            return
        }

        viewModelScope.launch {
            _nfcScanState.value = NfcScanUiState.Processing("Authenticating hardware chip & deriving Argon2id keys...")
            try {
                when (effectiveAction) {
                    NfcAction.SEAL_CARD -> {
                        val currentCard = _card.value ?: throw IllegalStateException("No card in memory to seal")
                        val container = withContext(Dispatchers.Default) {
                            EphemeralHandshakeEngine.sealCardToDevice(
                                coef = currentCard.coef,
                                civilIdUid = cardUid,
                                deviceUuid = deviceUuid,
                                passkeyBytes = passkey,
                                cardFp = currentCard.fingerprint
                            )
                        }
                        val file = File(filesDir, "sealed_card.qvseal")
                        file.writeText(container.serialize())
                        _sealedCardFp.value = currentCard.fingerprint
                        burnCard()
                        _nfcScanState.value = NfcScanUiState.Success("Card bound to Civil ID NFC chip and sealed to device!")
                        Log.i(TAG, "Card successfully bound to Civil ID hardware chip UID: ${cardUid.joinToString(":") { "%02X".format(it) }}")
                    }
                    NfcAction.RESTORE_CARD_TO_RAM -> {
                        val file = File(filesDir, "sealed_card.qvseal")
                        if (!file.exists()) throw IllegalStateException("No sealed card found on this device")
                        val container = EphemeralHandshakeEngine.SealedCardContainer.parse(file.readText())
                        val coef = withContext(Dispatchers.Default) {
                            EphemeralHandshakeEngine.unsealCardFromDevice(
                                container = container,
                                civilIdUid = cardUid,
                                deviceUuid = deviceUuid,
                                passkeyBytes = passkey
                            )
                        }
                        val restoredCard = withContext(Dispatchers.Default) {
                            QVaultEngine.cardFromCoef(coef)
                        }
                        _card.value = restoredCard
                        newChallenge()
                        _nfcScanState.value = NfcScanUiState.Success("Card ${container.cardFp} restored to memory from Civil ID chip!")
                        Log.i(TAG, "Card successfully restored to RAM via Civil ID NFC!")
                    }
                    NfcAction.SEAL_VAULT_PAYLOAD -> {
                        val file = File(filesDir, "sealed_card.qvseal")
                        if (!file.exists()) throw IllegalStateException("No sealed card found on this device")
                        val payloadInfo = pendingSealPayload ?: throw IllegalStateException("No payload prepared for sealing")
                        val container = EphemeralHandshakeEngine.SealedCardContainer.parse(file.readText())
                        val coef = withContext(Dispatchers.Default) {
                            EphemeralHandshakeEngine.unsealCardFromDevice(
                                container = container,
                                civilIdUid = cardUid,
                                deviceUuid = deviceUuid,
                                passkeyBytes = passkey
                            )
                        }
                        val mk = QVaultEngine.masterKey(coef)
                        val sealed = withContext(Dispatchers.Default) {
                            QVaultEngine.sealPayload(payloadInfo.bytes, payloadInfo.metaType, payloadInfo.metaName, mk, container.cardFp)
                        }
                        val finalPath: String
                        if (payloadInfo.outputStream != null) {
                            withContext(Dispatchers.IO) {
                                payloadInfo.outputStream.use { it.write(sealed) }
                            }
                            finalPath = payloadInfo.metaName ?: "Exported via SAF"
                        } else {
                            val dest = payloadInfo.destFolder ?: filesDir
                            if (!dest.exists()) dest.mkdirs()
                            val fname = if (payloadInfo.metaType == "text") {
                                "secret_message.qv5"
                            } else {
                                "${payloadInfo.metaName ?: "file"}.qv5"
                            }
                            val outFile = File(dest, fname)
                            outFile.writeBytes(sealed)
                            finalPath = outFile.absolutePath
                        }
                        pendingSealPayload = null
                        _sealState.value = SealState.Success(
                            fileName = finalPath,
                            size = sealed.size,
                            message = "Vault encrypted & sealed using Civil ID NFC hardware chip!"
                        )
                        _nfcScanState.value = NfcScanUiState.Success("Vault created and sealed with Civil ID NFC!")
                        Log.i(TAG, "Payload successfully sealed using Civil ID NFC token")
                    }
                    NfcAction.UNSEAL_VAULT -> {
                        val file = File(filesDir, "sealed_card.qvseal")
                        if (!file.exists()) throw IllegalStateException("No sealed card found on this device")
                        val container = EphemeralHandshakeEngine.SealedCardContainer.parse(file.readText())
                        val vaultFp = _loadedVaultCardFp.value
                        if (vaultFp != null && vaultFp != container.cardFp) {
                            throw IllegalStateException("Vault requires Card $vaultFp, but your Civil ID is bound to Card ${container.cardFp}")
                        }
                        val coef = withContext(Dispatchers.Default) {
                            EphemeralHandshakeEngine.unsealCardFromDevice(
                                container = container,
                                civilIdUid = cardUid,
                                deviceUuid = deviceUuid,
                                passkeyBytes = passkey
                            )
                        }
                        val mk = QVaultEngine.masterKey(coef)
                        val keyFingerprint = QVaultEngine.keyFp(mk)
                        val vault = _activeVaultBytes.value ?: throw IllegalStateException("No vault file loaded to unseal")
                        if (vault.isEmpty()) {
                            throw IllegalStateException("This vault file is empty (0 bytes). A previous export did not finish. Delete it and seal again.")
                        }
                        if (!vault.contains('\n'.code.toByte())) {
                            throw IllegalStateException("This file is not a QVault vault: the QV5 header is missing or the file is truncated.")
                        }
                        val (meta, payload) = try {
                            withContext(Dispatchers.Default) {
                                QVaultEngine.openPayload(vault, mk)
                            }
                        } catch (e: Exception) {
                            throw IllegalStateException("Decryption failed. Vault key does not match this Civil ID card.", e)
                        }
                        _unlockState.value = UnlockState.Success(
                            masterKeyFp = keyFingerprint,
                            metaType = meta.optString("type", "file"),
                            metaName = if (meta.isNull("name")) null else meta.optString("name"),
                            payload = payload
                        )
                        _nfcScanState.value = NfcScanUiState.Success("Vault unsealed instantly with Civil ID NFC!")
                        Log.i(TAG, "Vault unsealed via Civil ID NFC without typing!")
                    }
                    NfcAction.SIGN_CHALLENGE -> {
                        val file = File(filesDir, "sealed_card.qvseal")
                        if (!file.exists()) throw IllegalStateException("No sealed card found on this device")
                        val challengeStr = pendingChallengeToSign ?: throw IllegalArgumentException("Missing challenge payload to sign")
                        val challenge = EphemeralHandshakeEngine.ChallengeEnvelope.parse(challengeStr)
                        val container = EphemeralHandshakeEngine.SealedCardContainer.parse(file.readText())
                        val coef = withContext(Dispatchers.Default) {
                            EphemeralHandshakeEngine.unsealCardFromDevice(
                                container = container,
                                civilIdUid = cardUid,
                                deviceUuid = deviceUuid,
                                passkeyBytes = passkey
                            )
                        }
                        val response = withContext(Dispatchers.Default) {
                            EphemeralHandshakeEngine.createResponse(challenge, coef)
                        }
                        _generatedResponseQr.value = response.serialize()
                        _nfcScanState.value = NfcScanUiState.Success("Ephemeral Response Generated! Ready for peer scan.")
                        Log.i(TAG, "Ephemeral response signed via Civil ID NFC")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NFC Operation failed", e)
                _nfcScanState.value = NfcScanUiState.Error("NFC Authentication Failed: ${e.message}")
                clearCardCredentials()
                pendingSealPayload?.outputStream?.let {
                    closeQuietly(it)
                    _sealState.value = SealState.Error("Sealing failed after the Civil ID tap, so the exported file is empty: ${e.message}")
                }
                pendingSealPayload = null
            }
        }
    }

    // --- Wireless / Zero-Typing Ephemeral Handshake ---

    fun startEphemeralChallenge() {
        val vaultFp = _loadedVaultCardFp.value ?: ""
        val (challenge, priv) = EphemeralHandshakeEngine.createChallenge(vaultFp)
        activeVerifierPriv = priv
        activeChallengeEnvelope = challenge
        _activeChallengeQr.value = challenge.serialize()
        Log.i(TAG, "Ephemeral Challenge generated: TTL=60s")
    }

    fun dismissEphemeralChallenge() {
        activeVerifierPriv = null
        activeChallengeEnvelope = null
        _activeChallengeQr.value = null
    }

    fun resolveEphemeralResponse(responseStr: String) {
        val challenge = activeChallengeEnvelope
        val priv = activeVerifierPriv
        if (challenge == null || priv == null) {
            _unlockState.value = UnlockState.Error("No active pending challenge or key has expired")
            return
        }
        val vault = _activeVaultBytes.value
        if (vault == null) {
            _unlockState.value = UnlockState.Error("No vault file loaded to unseal")
            return
        }

        viewModelScope.launch {
            _unlockState.value = UnlockState.Verifying
            try {
                val response = EphemeralHandshakeEngine.ResponseEnvelope.parse(responseStr)
                val mk = withContext(Dispatchers.Default) {
                    EphemeralHandshakeEngine.processResponse(response, challenge, priv)
                }
                val (meta, payload) = withContext(Dispatchers.Default) {
                    QVaultEngine.openPayload(vault, mk)
                }
                _unlockState.value = UnlockState.Success(
                    masterKeyFp = QVaultEngine.keyFp(mk),
                    metaType = meta.optString("type", "file"),
                    metaName = if (meta.isNull("name")) null else meta.optString("name"),
                    payload = payload
                )
                dismissEphemeralChallenge()
                Log.i(TAG, "Vault unsealed via Ephemeral Peer Handshake!")
            } catch (e: Exception) {
                Log.e(TAG, "Ephemeral Handshake resolution failed", e)
                _unlockState.value = UnlockState.Error("Handshake failed: ${e.message}")
            }
        }
    }

    fun dismissGeneratedResponseQr() {
        _generatedResponseQr.value = null
    }
}

