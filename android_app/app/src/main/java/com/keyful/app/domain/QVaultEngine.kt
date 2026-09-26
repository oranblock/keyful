package com.keyful.app.domain

import org.bouncycastle.crypto.digests.SHAKEDigest
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object QVaultEngine {
    const val MAGIC = "QV5"
    const val VERSION = 2
    const val CHUNK = 1 shl 20
    const val SLIPS = 10
    const val CELLS = 14
    const val CELL_LEN = 4
    const val K = 13
    const val EXTRA = 2
    const val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private const val POLY = 0x100009
    private const val FBITS = 20
    private const val FMASK = (1 shl 20) - 1
    private val rng = SecureRandom()

    fun gmul(aInit: Int, bInit: Int): Int {
        var a = aInit
        var b = bInit
        var r = 0
        while (b != 0) {
            if ((b and 1) != 0) r = r xor a
            b = b ushr 1
            a = a shl 1
            if (((a ushr FBITS) and 1) != 0) a = a xor POLY
        }
        return r and FMASK
    }

    fun gpow(aInit: Int, eInit: Int): Int {
        var a = aInit
        var e = eInit
        var r = 1
        while (e != 0) {
            if ((e and 1) != 0) r = gmul(r, a)
            a = gmul(a, a)
            e = e ushr 1
        }
        return r
    }

    fun ginv(a: Int): Int = gpow(a, (1 shl FBITS) - 2)

    fun cellX(slip: Int, cell: Int): Int = (slip - 1) * CELLS + cell

    fun encCell(v: Int): String {
        val sb = StringBuilder(CELL_LEN)
        for (i in (CELL_LEN - 1) downTo 0) {
            sb.append(B32[(v ushr (5 * i)) and 31])
        }
        return sb.toString()
    }

    fun decCell(s: String): Int {
        var v = 0
        for (ch in s) {
            val idx = B32.indexOf(ch)
            if (idx >= 0) {
                v = (v shl 5) or idx
            }
        }
        return v
    }

    fun clean(input: String): String {
        val upper = input.replace("\\s+".toRegex(), "").uppercase()
        return upper.map { ch ->
            when (ch) {
                '0' -> 'O'
                '1' -> 'I'
                '8' -> 'B'
                '9' -> 'Q'
                else -> ch
            }
        }.joinToString("")
    }

    fun evaluate(coef: List<Int>, x: Int): Int {
        var y = 0
        for (a in coef.asReversed()) {
            y = gmul(y, x) xor a
        }
        return y
    }

    fun interpolate(pts: Map<Int, Int>): List<Int> {
        val xs = pts.keys.toList()
        val n = xs.size
        val coef = IntArray(n) { 0 }

        for (i in xs) {
            val num = IntArray(n) { 0 }
            num[0] = 1
            var den = 1
            var deg = 0
            for (j in xs) {
                if (i == j) continue
                val newPoly = IntArray(n) { 0 }
                for (d in 0..deg) {
                    newPoly[d] = newPoly[d] xor gmul(num[d], j)
                    if (d + 1 < n) {
                        newPoly[d + 1] = newPoly[d + 1] xor num[d]
                    }
                }
                for (idx in 0 until n) num[idx] = newPoly[idx]
                deg++
                den = gmul(den, i xor j)
            }
            val scale = gmul(pts[i] ?: 0, ginv(den))
            for (d in 0 until n) {
                coef[d] = coef[d] xor gmul(num[d], scale)
            }
        }
        return coef.toList()
    }

    fun cardFromCoef(coef: List<Int>): VaultCard {
        val card = mutableMapOf<Pair<Int, Int>, String>()
        for (s in 1..SLIPS) {
            for (c in 1..CELLS) {
                val x = cellX(s, c)
                val y = evaluate(coef, x)
                card[Pair(s, c)] = encCell(y)
            }
        }
        val cFp = cardFp(card)
        val mk = masterKey(coef)
        val kFp = keyFp(mk)
        return VaultCard(card, coef, cFp, kFp)
    }

    fun makeCard(): Pair<Map<Pair<Int, Int>, String>, List<Int>> {
        val coef = List(K) { rng.nextInt(1 shl FBITS) }
        val card = mutableMapOf<Pair<Int, Int>, String>()
        for (s in 1..SLIPS) {
            for (c in 1..CELLS) {
                val x = cellX(s, c)
                val y = evaluate(coef, x)
                card[Pair(s, c)] = encCell(y)
            }
        }
        return Pair(card, coef)
    }

    fun shake256(data: ByteArray, outLen: Int): ByteArray {
        val digest = SHAKEDigest(256)
        digest.update(data, 0, data.size)
        val out = ByteArray(outLen)
        digest.doFinal(out, 0, outLen)
        return out
    }

    fun masterKey(coef: List<Int>): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.write("QV5-MS".toByteArray(StandardCharsets.UTF_8))
        for (c in coef) {
            baos.write((c ushr 16) and 0xFF)
            baos.write((c ushr 8) and 0xFF)
            baos.write(c and 0xFF)
        }
        return shake256(baos.toByteArray(), 32)
    }

    fun keyFp(mk: ByteArray): String {
        val baos = ByteArrayOutputStream()
        baos.write("QV5-MK".toByteArray(StandardCharsets.UTF_8))
        baos.write(mk)
        val digest = shake256(baos.toByteArray(), 3)
        return digest.joinToString("") { "%02X".format(it) }
    }

    fun cardFp(card: Map<Pair<Int, Int>, String>): String {
        val sortedKeys = card.keys.sortedWith(compareBy({ it.first }, { it.second }))
        val baos = ByteArrayOutputStream()
        baos.write("QV5-CARD".toByteArray(StandardCharsets.UTF_8))
        for (k in sortedKeys) {
            baos.write((card[k] ?: "").toByteArray(StandardCharsets.UTF_8))
        }
        val digest = shake256(baos.toByteArray(), 3)
        return digest.joinToString("") { "%02X".format(it) }
    }

    fun kdf(mk: ByteArray, salt: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.write("QV5-KDF".toByteArray(StandardCharsets.UTF_8))
        baos.write(salt)
        baos.write(mk)
        return shake256(baos.toByteArray(), 32)
    }

    private fun sha256(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data)
    }

    private fun aadChunk(hdrAad: ByteArray, i: Long, last: Boolean): ByteArray {
        val h = sha256(hdrAad)
        val idxBytes = ByteBuffer.allocate(8).putLong(i).array()
        val flag = if (last) "F".toByteArray(StandardCharsets.UTF_8) else "C".toByteArray(StandardCharsets.UTF_8)
        return h + idxBytes + flag
    }

    fun freshChallenge(avoid: Set<Int> = emptySet()): List<Pair<Int, Int>> {
        var pool = mutableListOf<Pair<Int, Int>>()
        for (s in 1..SLIPS) {
            if (s !in avoid) {
                for (c in 1..CELLS) {
                    pool.add(Pair(s, c))
                }
            }
        }
        if (pool.size < (K + EXTRA)) {
            pool = mutableListOf()
            for (s in 1..SLIPS) {
                for (c in 1..CELLS) {
                    pool.add(Pair(s, c))
                }
            }
        }
        pool.shuffle(rng)
        return pool.take(K + EXTRA)
    }

    fun sealPayload(
        payloadBytes: ByteArray,
        metaType: String,
        metaName: String?,
        mk: ByteArray,
        magic: String = MAGIC,
        extraHeader: JSONObject? = null
    ): ByteArray {
        val salt = ByteArray(16).apply { rng.nextBytes(this) }
        val base = ByteArray(8).apply { rng.nextBytes(this) }

        val meta = JSONObject()
        meta.put("type", metaType)
        meta.put("name", metaName ?: JSONObject.NULL)
        meta.put("gz", false)
        meta.put("size", payloadBytes.size)
        val body = meta.toString().toByteArray(StandardCharsets.UTF_8)

        val head = ByteBuffer.allocate(2 + body.size).putShort(body.size.toShort()).put(body).array()

        val chunks = mutableListOf<Triple<Int, ByteArray, Boolean>>()
        var offset = 0
        var chunkIdx = 0
        val firstReadLen = minOf(CHUNK, payloadBytes.size)
        var buf = head + payloadBytes.copyOfRange(0, firstReadLen)
        offset += firstReadLen

        while (true) {
            val remaining = payloadBytes.size - offset
            if (remaining <= 0) {
                chunks.add(Triple(chunkIdx, buf, true))
                break
            }
            chunks.add(Triple(chunkIdx, buf, false))
            chunkIdx++
            val nextLen = minOf(CHUNK, remaining)
            buf = payloadBytes.copyOfRange(offset, offset + nextLen)
            offset += nextLen
        }
        val n = chunks.size

        val hdr = JSONObject()
        hdr.put("magic", magic)
        hdr.put("version", VERSION)
        hdr.put("cipher", "AES-256-GCM")
        hdr.put("kdf", "SHAKE256")
        hdr.put("k", K)
        hdr.put("chunks", n)
        hdr.put("salt", Base64.getEncoder().encodeToString(salt))
        hdr.put("base", Base64.getEncoder().encodeToString(base))
        // QV6/QV7 carry their lock sets here, so every chunk authenticates them too.
        extraHeader?.keys()?.forEach { hdr.put(it, extraHeader.get(it)) }

        val aad0 = hdr.toString().toByteArray(StandardCharsets.UTF_8)
        val key = kdf(mk, salt)

        val out = ByteArrayOutputStream()
        out.write(aad0)
        out.write("\n".toByteArray(StandardCharsets.UTF_8))

        try {
            for ((i, chunkData, isLast) in chunks) {
                var dataToEncrypt = chunkData
                if (n == 1 && dataToEncrypt.size < 4096) {
                    val pad = (256 - (dataToEncrypt.size % 256)) % 256
                    if (pad > 0) {
                        dataToEncrypt = dataToEncrypt + ByteArray(pad)
                    }
                }
                val nonce = base + ByteBuffer.allocate(4).putInt(i).array()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val spec = GCMParameterSpec(128, nonce)
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
                cipher.updateAAD(aadChunk(aad0, i.toLong(), isLast))
                val ct = cipher.doFinal(dataToEncrypt)

                out.write(ByteBuffer.allocate(4).putInt(ct.size).array())
                out.write(ct)
            }
            return out.toByteArray()
        } finally {
            key.fill(0.toByte())
        }
    }

    /**
     * Seals, then opens the result and compares it byte for byte, so a file that would not
     * open is never handed out.
     */
    fun sealVerified(payloadBytes: ByteArray, metaType: String, metaName: String?, mk: ByteArray): ByteArray {
        val sealed = sealPayload(payloadBytes, metaType, metaName, mk)
        val (meta, back) = openPayload(sealed, mk)
        try {
            check(back.contentEquals(payloadBytes) && meta.optString("type") == metaType) {
                "Self-test failed: the sealed file did not open back to the same data. Nothing was saved."
            }
        } finally {
            back.fill(0)
        }
        return sealed
    }

    private const val NAME_CHARS = "abcdefghjkmnpqrstuvwxyz23456789"

    /** A random vault file name: the name must not reveal what is inside or which card opens it. */
    fun vaultFileName(ext: String = "qv5"): String =
        "vault-" + String(CharArray(6) { NAME_CHARS[rng.nextInt(NAME_CHARS.length)] }) + "." + ext

    fun openPayload(vaultBytes: ByteArray, mk: ByteArray): Pair<JSONObject, ByteArray> {
        val newlineIdx = vaultBytes.indexOf('\n'.code.toByte())
        if (newlineIdx < 0) error("Invalid vault header: missing newline")

        val aad0 = vaultBytes.copyOfRange(0, newlineIdx)
        val rest = vaultBytes.copyOfRange(newlineIdx + 1, vaultBytes.size)
        val hdr = JSONObject(String(aad0, StandardCharsets.UTF_8))

        val salt = Base64.getDecoder().decode(hdr.getString("salt"))
        val key = kdf(mk, salt)

        try {
            // v1 vault: single blob, text only, nonce instead of base
            if (!hdr.has("chunks") || hdr.has("nonce")) {
                val nonce = Base64.getDecoder().decode(hdr.getString("nonce"))
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val spec = GCMParameterSpec(128, nonce)
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
                cipher.updateAAD(aad0)
                val body = cipher.doFinal(rest)
                val n = ByteBuffer.wrap(body, 0, 4).int
                val payload = body.copyOfRange(4, 4 + n)
                val meta = JSONObject()
                meta.put("type", "text")
                meta.put("name", JSONObject.NULL)
                meta.put("gz", false)
                meta.put("size", n)
                return Pair(meta, payload)
            }

            // v2 vault: chunked AES-256-GCM
            val base = Base64.getDecoder().decode(hdr.getString("base"))
            val chunksCount = hdr.optInt("chunks", 1)
            var off = 0
            var meta: JSONObject? = null
            val out = ByteArrayOutputStream()

            for (i in 0 until chunksCount) {
                val ln = ByteBuffer.wrap(rest, off, 4).int
                off += 4
                val ct = rest.copyOfRange(off, off + ln)
                off += ln

                val nonce = base + ByteBuffer.allocate(4).putInt(i).array()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val spec = GCMParameterSpec(128, nonce)
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
                val isLast = (i == chunksCount - 1)
                cipher.updateAAD(aadChunk(aad0, i.toLong(), isLast))
                val pt = cipher.doFinal(ct)

                if (i == 0) {
                    val ml = ByteBuffer.wrap(pt, 0, 2).short.toInt() and 0xFFFF
                    val metaBytes = pt.copyOfRange(2, 2 + ml)
                    meta = JSONObject(String(metaBytes, StandardCharsets.UTF_8))
                    out.write(pt.copyOfRange(2 + ml, pt.size))
                } else {
                    out.write(pt)
                }
            }

            var data = out.toByteArray()
            val origSize = if (meta != null && meta.has("size")) meta.getInt("size") else data.size
            if (data.size > origSize) {
                data = data.copyOfRange(0, origSize)
            }

            return Pair(meta ?: JSONObject(), data)
        } finally {
            key.fill(0.toByte())
        }
    }
}
