package com.keyful.app.domain

import com.keyful.app.voicelab.VoiceLock
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher

/**
 * QV6 / QV7 vaults: a few cells of the paper card + your voice (QV6), plus a passphrase (QV7).
 * Every factor is key material; the app never decides on its own that a factor passed.
 *
 *   cellSecret, voiceSecret = 32 random bytes each
 *   vaultKey   = SHAKE256("QV67-KEY" ‖ magic ‖ cellSecret ‖ voiceSecret)
 *   cell lock i (CELL_LOCKS of them): a random N-cell subset S_i of the card,
 *                AES-GCM( Argon2id(values of S_i ‖ i, salt_i, 8 MiB), cellSecret )
 *   voice lock = VoiceLock(passphrase or none, voiceprint, voiceSecret, bind = cellSecret)
 *   payload    = the QV5 chunked AES-256-GCM container keyed by vaultKey; both lock sets sit
 *                in its header line, which every chunk authenticates.
 *
 * Unlock: the app picks a random cell lock and asks for its N cells. The right cells give
 * cellSecret; the voice (+ passphrase) then opens the voice lock; both give vaultKey.
 * Without the card, N cells are 20·N bits (60 at N = 3) behind Argon2. With the card, QV6
 * rests on the voice alone (~12 bits per voice lock); QV7's passphrase is what holds then.
 */
object VoiceVault {
    const val QV6 = "QV6"
    const val QV7 = "QV7"
    const val MIN_CELLS = 3
    const val MAX_CELLS = QVaultEngine.K
    const val CELL_LOCKS = 32
    /** The voiceprint model is part of the key: another model gives other bits. */
    const val VOICE_MODEL = "vosk-model-spk-0.4"

    private const val CELL_MEM_KB = 8 * 1024
    private const val SECRET = 32
    private const val CELL_CT = SECRET + 16
    private val CELL_TAG = "QV67-CELLS".toByteArray(StandardCharsets.UTF_8)
    private val KEY_TAG = "QV67-KEY".toByteArray(StandardCharsets.UTF_8)
    private val rng = SecureRandom()

    class CellLock(val xs: IntArray, val salt: ByteArray, val nonce: ByteArray, val ct: ByteArray)

    class Parsed(val magic: String, val cells: Int, val cardFp: String?, val cellLocks: List<CellLock>, val voiceLock: ByteArray) {
        val withPass: Boolean get() = magic == QV7
    }

    class Opened(val meta: JSONObject, val payload: ByteArray, val keyFp: String)

    fun isVoiceFormat(magic: String?) = magic == QV6 || magic == QV7

    private fun rand(n: Int) = ByteArray(n).also { rng.nextBytes(it) }

    private fun cellAad(i: Int) = CELL_TAG + ByteBuffer.allocate(4).putInt(i).array()

    private fun cellInput(i: Int, xs: IntArray, ys: IntArray): ByteArray {
        val b = ByteBuffer.allocate(CELL_TAG.size + 4 + 4 * xs.size)
        b.put(CELL_TAG).putInt(i)
        for (k in xs.indices) {
            b.put(xs[k].toByte()).put((ys[k] ushr 16).toByte()).put((ys[k] ushr 8).toByte()).put(ys[k].toByte())
        }
        return b.array()
    }

    private fun vaultKey(magic: String, cellSecret: ByteArray, voiceSecret: ByteArray): ByteArray {
        val input = KEY_TAG + magic.toByteArray(StandardCharsets.UTF_8) + cellSecret + voiceSecret
        try {
            val d = SHAKEDigest(256); d.update(input, 0, input.size)
            return ByteArray(32).also { d.doFinal(it, 0, 32) }
        } finally { input.fill(0) }
    }

    /** Card coordinates (slip, cell) for a cell index x in 1..140. */
    fun coordOf(x: Int) = Pair((x - 1) / QVaultEngine.CELLS + 1, (x - 1) % QVaultEngine.CELLS + 1)

    fun seal(
        payload: ByteArray, metaType: String, metaName: String?, card: VaultCard,
        magic: String, cells: Int, voice: FloatArray, pass: CharArray
    ): ByteArray {
        require(isVoiceFormat(magic)) { "not a voice format: $magic" }
        require(cells in MIN_CELLS..MAX_CELLS) { "cells must be $MIN_CELLS..$MAX_CELLS" }
        require(magic == QV6 || pass.isNotEmpty()) { "QV7 needs a passphrase" }
        val cellSecret = rand(SECRET)
        val voiceSecret = rand(SECRET)
        try {
            val all = (1..QVaultEngine.SLIPS * QVaultEngine.CELLS).toList()
            val locks = ByteArrayOutputStream()
            val o = DataOutputStream(locks)
            o.writeInt(CELL_LOCKS)
            for (i in 0 until CELL_LOCKS) {
                val xs = all.shuffled(rng).take(cells).toIntArray()
                val ys = IntArray(cells) { QVaultEngine.evaluate(card.coef, xs[it]) }
                val salt = rand(16); val nonce = rand(12)
                val input = cellInput(i, xs, ys)
                val k = VoiceLock.argon(input, salt, CELL_MEM_KB, 1)
                input.fill(0); ys.fill(0)
                val ct = try { VoiceLock.gcm(Cipher.ENCRYPT_MODE, k, nonce, cellAad(i), cellSecret) } finally { k.fill(0) }
                xs.forEach { o.writeByte(it) }
                o.write(salt); o.write(nonce); o.write(ct)
            }
            o.flush()
            val voiceLock = VoiceLock.sealBytes(if (magic == QV7) pass else CharArray(0), voice, voiceSecret, cellSecret)
            val extra = JSONObject()
                .put("cells", cells)
                .put("voice", VOICE_MODEL)
                .put("clocks", Base64.getEncoder().encodeToString(locks.toByteArray()))
                .put("vlock", Base64.getEncoder().encodeToString(voiceLock))
            val key = vaultKey(magic, cellSecret, voiceSecret)
            try {
                return QVaultEngine.sealPayload(payload, metaType, metaName, key, card.fingerprint, magic, extra)
            } finally { key.fill(0) }
        } finally {
            cellSecret.fill(0); voiceSecret.fill(0)
        }
    }

    /** null = not a QV6/QV7 file (e.g. QV5). Throws if it claims QV6/QV7 but is damaged. */
    fun parse(vault: ByteArray): Parsed? {
        val nl = vault.indexOf('\n'.code.toByte())
        if (nl <= 0) return null
        val hdr = try { JSONObject(String(vault, 0, nl, StandardCharsets.UTF_8)) } catch (_: Exception) { return null }
        val magic = hdr.optString("magic", "")
        if (!isVoiceFormat(magic)) return null
        val cells = hdr.optInt("cells", -1)
        require(cells in MIN_CELLS..MAX_CELLS) { "damaged $magic header: cells=$cells" }
        val inp = DataInputStream(ByteArrayInputStream(Base64.getDecoder().decode(hdr.getString("clocks"))))
        val count = inp.readInt()
        require(count in 1..1024) { "damaged $magic header: $count cell locks" }
        val max = QVaultEngine.SLIPS * QVaultEngine.CELLS
        val locks = List(count) {
            val xs = IntArray(cells) { inp.readUnsignedByte() }
            require(xs.all { it in 1..max } && xs.distinct().size == cells) { "damaged $magic header: bad cell index" }
            val salt = ByteArray(16).also { inp.readFully(it) }
            val nonce = ByteArray(12).also { inp.readFully(it) }
            val ct = ByteArray(CELL_CT).also { inp.readFully(it) }
            CellLock(xs, salt, nonce, ct)
        }
        val card = if (hdr.has("card")) hdr.getString("card") else null
        return Parsed(magic, cells, card, locks, Base64.getDecoder().decode(hdr.getString("vlock")))
    }

    /** The card coordinates cell lock `lock` asks for, in order. */
    fun challenge(p: Parsed, lock: Int): List<Pair<Int, Int>> = p.cellLocks[lock].xs.map { coordOf(it) }

    /** cellSecret if these typed cells are right for `lock`, else null. */
    fun openCells(p: Parsed, lock: Int, typed: List<String>): ByteArray? {
        val cl = p.cellLocks[lock]
        if (typed.size != cl.xs.size) return null
        val ys = IntArray(typed.size) { QVaultEngine.decCell(QVaultEngine.clean(typed[it])) }
        val input = cellInput(lock, cl.xs, ys)
        val k = VoiceLock.argon(input, cl.salt, CELL_MEM_KB, 1)
        input.fill(0); ys.fill(0)
        return try {
            VoiceLock.gcm(Cipher.DECRYPT_MODE, k, cl.nonce, cellAad(lock), cl.ct)
        } catch (_: Exception) {
            null
        } finally { k.fill(0) }
    }

    /**
     * Opens the vault once the cells gave cellSecret. null = the voice lock stayed shut
     * (voice or passphrase did not fit). Throws if the payload itself is damaged.
     */
    fun open(vault: ByteArray, p: Parsed, cellSecret: ByteArray, voice: FloatArray, pass: CharArray): Opened? {
        val o = VoiceLock.openBytes(if (p.withPass) pass else CharArray(0), voice, p.voiceLock, cellSecret) ?: return null
        val key = try { vaultKey(p.magic, cellSecret, o.secret) } finally { o.secret.fill(0) }
        try {
            val (meta, payload) = QVaultEngine.openPayload(vault, key)
            return Opened(meta, payload, QVaultEngine.keyFp(key))
        } finally { key.fill(0) }
    }
}
