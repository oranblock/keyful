package com.keyful.app.voicelab

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/**
 * Voice + passphrase lock — the voice is part of the key math, not an app check.
 *
 * Multi-factor fuzzy extractor using sample-then-lock (Canetti et al., "Reusable Fuzzy
 * Extractors for Low-Entropy Distributions"):
 *   kPass  = Argon2id(passphrase, salt, 64 MiB, 3 passes)
 *   pool   = the POOL strongest dimensions of the enrolled voiceprint (sign = key bit)
 *   lock j = AES-GCM( Argon2id(kPass ‖ voiceBits[subset_j] ‖ j, salt_j, 8 MiB, 1), vaultKey )
 *   data   = AES-GCM( vaultKey, secret )
 * Opening needs the passphrase AND a voice whose bits match EXACTLY on at least one
 * random subset of K dimensions. The voiceprint itself is never stored — only locks —
 * so the file does not leak the voice bits. The app cannot tell which factor failed:
 * the lock simply does not open.
 *
 * An empty passphrase means no passphrase factor. `bind` (optional) mixes another secret
 * into every lock key, so the voice locks cannot even be tried without it (QV6/QV7 bind
 * them to the secret the paper-card cells open).
 *
 * Math floor for a random wrong voice with the right passphrase: about L / 2^K
 * (64 / 4096 ≈ 1.6%). Real similar voices do better than random; the passphrase stays
 * the main strength. Recovery if the voice changes for good = the paper card.
 */
object VoiceLock {
    const val POOL = 64
    const val K = 12
    const val L = 64

    private val MAGIC = "KVL1".toByteArray()
    private val DATA_AAD = "KVL1data".toByteArray()
    private val BIND_TAG = "KVL1bind".toByteArray()
    private val rng = SecureRandom()

    class Opened(val secret: ByteArray, val lockIndex: Int)

    internal fun argon(input: ByteArray, salt: ByteArray, memKb: Int, iters: Int): ByteArray {
        val p = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iters).withMemoryAsKB(memKb).withParallelism(1)
            .withSalt(salt).build()
        val g = Argon2BytesGenerator(); g.init(p)
        val out = ByteArray(32); g.generateBytes(input, out)
        return out
    }

    private fun passKey(pass: CharArray, salt: ByteArray): ByteArray {
        val pw = String(pass).toByteArray(Charsets.UTF_8)
        try { return argon(pw, salt, 64 * 1024, 3) } finally { pw.fill(0) }
    }

    /** Passphrase key (none = zeros), with `bind` mixed in when given. */
    private fun factorKey(pass: CharArray, salt: ByteArray, bind: ByteArray): ByteArray {
        val kp = if (pass.isEmpty()) ByteArray(32) else passKey(pass, salt)
        if (bind.isEmpty()) return kp
        val input = BIND_TAG + kp + bind
        try { return MessageDigest.getInstance("SHA-256").digest(input) } finally { kp.fill(0); input.fill(0) }
    }

    private fun voiceBits(voice: FloatArray, subset: ByteArray): ByteArray {
        val out = ByteArray((subset.size + 7) / 8)
        subset.forEachIndexed { i, d ->
            if (voice[d.toInt() and 0xFF] > 0f) out[i / 8] = (out[i / 8].toInt() or (1 shl (i % 8))).toByte()
        }
        return out
    }

    private fun lockKey(kPass: ByteArray, bits: ByteArray, j: Int, salt: ByteArray): ByteArray {
        val input = kPass + bits + ByteBuffer.allocate(4).putInt(j).array()
        try { return argon(input, salt, 8 * 1024, 1) } finally { input.fill(0) }
    }

    private fun lockAad(j: Int) = MAGIC + ByteBuffer.allocate(4).putInt(j).array()

    internal fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(data)
    }

    private fun rand(n: Int) = ByteArray(n).also { rng.nextBytes(it) }

    fun sealBytes(pass: CharArray, voice: FloatArray, secret: ByteArray, bind: ByteArray = ByteArray(0)): ByteArray {
        require(voice.size in POOL..255) { "voiceprint has ${voice.size} dims" }
        val vaultKey = rand(32)
        val passSalt = rand(16)
        val kPass = factorKey(pass, passSalt, bind)
        val pool = voice.indices.sortedByDescending { abs(voice[it]) }.take(POOL)
        val bos = ByteArrayOutputStream()
        val o = DataOutputStream(bos)
        try {
            o.write(MAGIC); o.write(passSalt)
            o.writeInt(voice.size); o.writeInt(L); o.writeInt(K)
            for (j in 0 until L) {
                val subset = pool.shuffled(rng).take(K).map { it.toByte() }.toByteArray()
                val salt = rand(16); val nonce = rand(12)
                val bits = voiceBits(voice, subset)
                val kj = lockKey(kPass, bits, j, salt)
                val ct = gcm(Cipher.ENCRYPT_MODE, kj, nonce, lockAad(j), vaultKey)
                kj.fill(0); bits.fill(0)
                o.write(subset); o.write(salt); o.write(nonce); o.writeInt(ct.size); o.write(ct)
            }
            val dataNonce = rand(12)
            val dataCt = gcm(Cipher.ENCRYPT_MODE, vaultKey, dataNonce, DATA_AAD, secret)
            o.write(dataNonce); o.writeInt(dataCt.size); o.write(dataCt)
            o.flush()
            return bos.toByteArray()
        } finally {
            kPass.fill(0); vaultKey.fill(0)
        }
    }

    /** null = the lock stayed shut: wrong passphrase, voice too different, or tampered file. */
    fun openBytes(pass: CharArray, voice: FloatArray, blob: ByteArray, bind: ByteArray = ByteArray(0)): Opened? {
        return try {
            val inp = DataInputStream(ByteArrayInputStream(blob))
            val magic = ByteArray(4); inp.readFully(magic)
            if (!magic.contentEquals(MAGIC)) return null
            val passSalt = ByteArray(16); inp.readFully(passSalt)
            val dim = inp.readInt(); val l = inp.readInt(); val k = inp.readInt()
            if (dim != voice.size || l !in 1..1024 || k !in 1..64) return null

            val kPass = factorKey(pass, passSalt, bind)
            var vaultKey: ByteArray? = null
            var which = -1
            try {
                for (j in 0 until l) {
                    val subset = ByteArray(k); inp.readFully(subset)
                    val salt = ByteArray(16); inp.readFully(salt)
                    val nonce = ByteArray(12); inp.readFully(nonce)
                    val n = inp.readInt(); if (n !in 16..4096) return null
                    val ct = ByteArray(n); inp.readFully(ct)
                    if (vaultKey != null) continue          // already open; just consume the stream
                    if (subset.any { (it.toInt() and 0xFF) >= dim }) return null
                    val bits = voiceBits(voice, subset)
                    val kj = lockKey(kPass, bits, j, salt)
                    try {
                        vaultKey = gcm(Cipher.DECRYPT_MODE, kj, nonce, lockAad(j), ct); which = j
                    } catch (_: Exception) {
                        // this subset of the voice did not match; try the next lock
                    } finally { kj.fill(0); bits.fill(0) }
                }
            } finally { kPass.fill(0) }

            val key = vaultKey ?: return null
            val dataNonce = ByteArray(12); inp.readFully(dataNonce)
            val n = inp.readInt(); if (n !in 16..(16 * 1024 * 1024)) return null
            val dataCt = ByteArray(n); inp.readFully(dataCt)
            try { Opened(gcm(Cipher.DECRYPT_MODE, key, dataNonce, DATA_AAD, dataCt), which) }
            finally { key.fill(0) }
        } catch (_: Exception) {
            null
        }
    }

    private const val FILE = "voice_lock.bin"

    fun exists(dir: File) = File(dir, FILE).exists()
    fun seal(dir: File, pass: CharArray, voice: FloatArray, secret: ByteArray) =
        File(dir, FILE).writeBytes(sealBytes(pass, voice, secret))
    fun open(dir: File, pass: CharArray, voice: FloatArray): Opened? =
        if (!exists(dir)) null else openBytes(pass, voice, File(dir, FILE).readBytes())
    fun wipe(dir: File) { File(dir, FILE).delete() }
}
