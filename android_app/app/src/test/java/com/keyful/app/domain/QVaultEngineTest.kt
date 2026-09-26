package com.keyful.app.domain

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class QVaultEngineTest {

    private fun sha256Hex(data: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }

    @Test
    fun testSealVerifiedRoundTripAndNoFingerprints() {
        val (_, coef) = QVaultEngine.makeCard()
        val mk = QVaultEngine.masterKey(coef)
        val data = "sealed and test-opened".toByteArray(StandardCharsets.UTF_8)
        val sealed = QVaultEngine.sealVerified(data, "text", null, mk)
        val (meta, back) = QVaultEngine.openPayload(sealed, mk)
        assertEquals("text", meta.getString("type"))
        assertArrayEquals(data, back)
        val nl = sealed.indexOf('\n'.code.toByte())
        val hdr = JSONObject(String(sealed, 0, nl, StandardCharsets.UTF_8))
        assertFalse(hdr.has("card"))
        assertFalse(hdr.has("key"))
    }

    @Test
    fun testVaultFileNameIsRandomAndRevealsNothing() {
        val names = List(50) { QVaultEngine.vaultFileName() }
        names.forEach { assertTrue(it, Regex("vault-[a-z2-9]{6}\\.qv5").matches(it)) }
        assertTrue("names should not repeat", names.toSet().size > 45)
        assertTrue(Regex("vault-[a-z2-9]{6}\\.qv7").matches(QVaultEngine.vaultFileName("qv7")))
    }

    @Test
    fun testCardFromCoefDeterministic() {
        val (cardMap, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(cardMap)
        val mk = QVaultEngine.masterKey(coef)
        val kFp = QVaultEngine.keyFp(mk)

        val restored = QVaultEngine.cardFromCoef(coef)
        assertEquals(cFp, restored.fingerprint)
        assertEquals(kFp, restored.keyFingerprint)
        assertEquals(cardMap.size, restored.cells.size)
        for ((k, v) in cardMap) {
            assertEquals("Cell at $k must match", v, restored.cells[k])
        }
    }

    @Test
    fun testTextRoundTripSha256() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        val plaintext = "Top secret message from paper card: 12345! @#$ QVault".toByteArray(StandardCharsets.UTF_8)
        val origSha = sha256Hex(plaintext)

        val sealed = QVaultEngine.sealPayload(plaintext, "text", null, mk)
        assertNotNull(sealed)
        assertTrue(sealed.isNotEmpty())

        val (meta, decrypted) = QVaultEngine.openPayload(sealed, mk)
        assertEquals("text", meta.getString("type"))
        assertEquals(origSha, sha256Hex(decrypted))
        assertEquals(String(plaintext, StandardCharsets.UTF_8), String(decrypted, StandardCharsets.UTF_8))
    }

    @Test
    fun testSmallFileRoundTripSha256() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        val smallData = ByteArray(77) { (it * 3 % 256).toByte() }
        val origSha = sha256Hex(smallData)

        val sealed = QVaultEngine.sealPayload(smallData, "file", "small.dat", mk)
        val (meta, decrypted) = QVaultEngine.openPayload(sealed, mk)

        assertEquals("file", meta.getString("type"))
        assertEquals("small.dat", meta.getString("name"))
        assertEquals(77, decrypted.size)
        assertEquals(origSha, sha256Hex(decrypted))
    }

    @Test
    fun testMultiChunkRoundTripSha256() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        // 2.5 MiB payload -> spans 3 chunks (chunk size = 1 MiB)
        val largeSize = (2.5 * 1024 * 1024).toInt()
        val largeData = ByteArray(largeSize)
        val rng = SecureRandom()
        rng.nextBytes(largeData)
        val origSha = sha256Hex(largeData)

        val sealed = QVaultEngine.sealPayload(largeData, "file", "large_archive.bin", mk)

        // Verify header chunks count
        val nl = sealed.indexOf('\n'.code.toByte())
        val hdr = JSONObject(String(sealed.copyOfRange(0, nl), StandardCharsets.UTF_8))
        assertEquals(3, hdr.getInt("chunks"))

        val (meta, decrypted) = QVaultEngine.openPayload(sealed, mk)
        assertEquals("file", meta.getString("type"))
        assertEquals("large_archive.bin", meta.getString("name"))
        assertEquals(largeSize, decrypted.size)
        assertEquals(origSha, sha256Hex(decrypted))
    }

    @Test
    fun testDirectoryPayloadRoundTripSha256() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        val tarBytes = "Mock tar.gz payload contents for directory backup".toByteArray(StandardCharsets.UTF_8)
        val origSha = sha256Hex(tarBytes)

        val sealed = QVaultEngine.sealPayload(tarBytes, "dir", "keys_backup.tar.gz", mk)
        val (meta, decrypted) = QVaultEngine.openPayload(sealed, mk)

        assertEquals("dir", meta.getString("type"))
        assertEquals("keys_backup.tar.gz", meta.getString("name"))
        assertEquals(origSha, sha256Hex(decrypted))
    }

    @Test
    fun testWrongCardPolynomialMismatch() {
        val (cardA, coefA) = QVaultEngine.makeCard()
        val (cardB, coefB) = QVaultEngine.makeCard()

        val mkA = QVaultEngine.masterKey(coefA)
        val mkB = QVaultEngine.masterKey(coefB)
        val cFpA = QVaultEngine.cardFp(cardA)

        val data = "Confidential financial data".toByteArray(StandardCharsets.UTF_8)
        val sealedA = QVaultEngine.sealPayload(data, "text", null, mkA)

        // Attempt decrypt with wrong master key B -> must throw AEADBadTagException / error
        try {
            QVaultEngine.openPayload(sealedA, mkB)
            fail("Expected decryption failure with wrong key, but succeeded")
        } catch (e: Exception) {
            // Expected decryption failure
            assertNotNull(e)
        }
    }

    @Test
    fun testSingleMistypedCellDetection() {
        val (card, coef) = QVaultEngine.makeCard()
        val challengeCoords = QVaultEngine.freshChallenge()
        assertEquals(15, challengeCoords.size)

        // Perfect cells
        val originalValues = challengeCoords.associateWith { card[it]!! }

        // Test 1: Perfect cells reconstruct identical polynomial and evaluate cleanly
        val pts = challengeCoords.take(13).associate {
            QVaultEngine.cellX(it.first, it.second) to QVaultEngine.decCell(originalValues[it]!!)
        }
        val reconstructedCoef = QVaultEngine.interpolate(pts)
        assertEquals(coef, reconstructedCoef)

        val checkBad = challengeCoords.drop(13).filter {
            val expectedY = QVaultEngine.evaluate(reconstructedCoef, QVaultEngine.cellX(it.first, it.second))
            val actualY = QVaultEngine.decCell(originalValues[it]!!)
            expectedY != actualY
        }
        assertTrue("Expected 0 bad cells with authentic card cells", checkBad.isEmpty())

        // Test 2: Corrupt 1 cell in the first 13 cells
        val corruptedValues1 = originalValues.toMutableMap()
        val firstKey = challengeCoords[0]
        val origCellStr = corruptedValues1[firstKey]!!
        val swappedChar = if (origCellStr[0] == 'A') 'B' else 'A'
        corruptedValues1[firstKey] = swappedChar + origCellStr.substring(1)

        val ptsCorrupted1 = challengeCoords.take(13).associate {
            QVaultEngine.cellX(it.first, it.second) to QVaultEngine.decCell(corruptedValues1[it]!!)
        }
        val badPoly = QVaultEngine.interpolate(ptsCorrupted1)
        val badCheck1 = challengeCoords.drop(13).filter {
            val expectedY = QVaultEngine.evaluate(badPoly, QVaultEngine.cellX(it.first, it.second))
            val actualY = QVaultEngine.decCell(corruptedValues1[it]!!)
            expectedY != actualY
        }
        assertTrue("Mistyped cell in K cells must trigger check cell discrepancy", badCheck1.isNotEmpty())

        // Test 3: Corrupt 1 cell in the check cells (14 or 15)
        val corruptedValues2 = originalValues.toMutableMap()
        val checkKey = challengeCoords[14]
        val origCheckStr = corruptedValues2[checkKey]!!
        val swappedChar2 = if (origCheckStr[0] == 'X') 'Y' else 'X'
        corruptedValues2[checkKey] = swappedChar2 + origCheckStr.substring(1)

        val badCheck2 = challengeCoords.drop(13).filter {
            val expectedY = QVaultEngine.evaluate(reconstructedCoef, QVaultEngine.cellX(it.first, it.second))
            val actualY = QVaultEngine.decCell(corruptedValues2[it]!!)
            expectedY != actualY
        }
        assertEquals("Mistyped check cell must be caught", listOf(checkKey), badCheck2)
    }

    @Test
    fun testTruncatedCiphertextFailure() {
        val (card, coef) = QVaultEngine.makeCard()
        val mk = QVaultEngine.masterKey(coef)
        val cFp = QVaultEngine.cardFp(card)

        val data = "Payload to test integrity verification".toByteArray(StandardCharsets.UTF_8)
        val sealed = QVaultEngine.sealPayload(data, "text", null, mk)

        // Truncate last 8 bytes (corrupting GCM authentication tag)
        val truncated = sealed.copyOfRange(0, sealed.size - 8)

        try {
            QVaultEngine.openPayload(truncated, mk)
            fail("Truncated ciphertext must fail decryption")
        } catch (e: Exception) {
            // Expected AEADBadTagException or EOF
            assertTrue(true)
        }
    }

    @Test
    fun testV1HeaderCompatibility() {
        // Construct a legacy v1 vault
        val (card, coef) = QVaultEngine.makeCard()
        val mk = QVaultEngine.masterKey(coef)
        val cFp = QVaultEngine.cardFp(card)

        val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
        val nonce = ByteArray(12).apply { SecureRandom().nextBytes(this) }

        val hdr = JSONObject()
        hdr.put("magic", "QV5")
        hdr.put("version", 1)
        hdr.put("cipher", "AES-256-GCM")
        hdr.put("kdf", "SHAKE256")
        hdr.put("card", cFp)
        hdr.put("salt", Base64.getEncoder().encodeToString(salt))
        hdr.put("nonce", Base64.getEncoder().encodeToString(nonce))

        val aad0 = hdr.toString().toByteArray(StandardCharsets.UTF_8)
        val key = QVaultEngine.kdf(mk, salt)

        val msg = "Legacy v1 vault text payload".toByteArray(StandardCharsets.UTF_8)
        val body = ByteBuffer.allocate(4 + msg.size).putInt(msg.size).put(msg).array()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        cipher.updateAAD(aad0)
        val ct = cipher.doFinal(body)

        val baos = ByteArrayOutputStream()
        baos.write(aad0)
        baos.write("\n".toByteArray(StandardCharsets.UTF_8))
        baos.write(ct)
        val v1VaultBytes = baos.toByteArray()

        val (meta, decrypted) = QVaultEngine.openPayload(v1VaultBytes, mk)
        assertEquals("text", meta.getString("type"))
        assertEquals("Legacy v1 vault text payload", String(decrypted, StandardCharsets.UTF_8))
    }

    @Test
    fun testMemoryZeroing() {
        val sensitiveData = "SuperSecretPlainText12345".toByteArray(StandardCharsets.UTF_8)
        val successState = UnlockState.Success(
            masterKeyFp = "123456",
            metaType = "text",
            metaName = null,
            payload = sensitiveData
        )

        // Verify before wipe
        assertFalse(sensitiveData.all { it == 0.toByte() })

        // Wipe
        successState.wipe()

        // Verify every byte is 0
        assertTrue(sensitiveData.all { it == 0.toByte() })
    }

    @Test
    fun testExactChunkBoundarySizes() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        val oneMib = 1 shl 20
        val boundarySizes = listOf(
            0,
            1,
            255,
            256,
            oneMib,
            oneMib + 1,
            2 * oneMib
        )

        for (size in boundarySizes) {
            val data = ByteArray(size) { (it % 256).toByte() }
            val origSha = sha256Hex(data)

            val sealed = QVaultEngine.sealPayload(data, "file", "boundary_$size.bin", mk)

            val nl = sealed.indexOf('\n'.code.toByte())
            val hdr = JSONObject(String(sealed.copyOfRange(0, nl), StandardCharsets.UTF_8))
            val expectedChunks = when {
                size <= oneMib -> 1
                size <= 2 * oneMib -> 2
                else -> (size + oneMib - 1) / oneMib
            }
            assertEquals("Chunk count mismatch for size $size", expectedChunks, hdr.getInt("chunks"))

            val (meta, decrypted) = QVaultEngine.openPayload(sealed, mk)
            assertEquals("Decrypted size mismatch for size $size", size, decrypted.size)
            assertEquals("Decrypted SHA-256 mismatch for size $size", origSha, sha256Hex(decrypted))
        }
    }

    @Test
    fun testUnicodeAndEdgeStrings() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        val testStrings = listOf(
            "سري للغاية: كلمة السر للخزنة ٢٠٢٦ - مفتاح الأمان للبطاقة الورقية",
            "🔐🛡️🔑 Top Secret Vault 🚀✨💥🏷️",
            ""
        )

        for (str in testStrings) {
            val bytes = str.toByteArray(StandardCharsets.UTF_8)
            val origSha = sha256Hex(bytes)

            val sealed = QVaultEngine.sealPayload(bytes, "text", null, mk)
            val (meta, decrypted) = QVaultEngine.openPayload(sealed, mk)

            assertEquals("text", meta.getString("type"))
            assertEquals(origSha, sha256Hex(decrypted))
            assertEquals(str, String(decrypted, StandardCharsets.UTF_8))
        }
    }

    @Test
    fun testChunkTamperingPermutationAndSplicing() {
        val (cardA, coefA) = QVaultEngine.makeCard()
        val mkA = QVaultEngine.masterKey(coefA)
        val cFpA = QVaultEngine.cardFp(cardA)

        val (cardB, coefB) = QVaultEngine.makeCard()
        val mkB = QVaultEngine.masterKey(coefB)
        val cFpB = QVaultEngine.cardFp(cardB)

        // 2.5 MiB payload -> 3 chunks
        val size = (2.5 * 1024 * 1024).toInt()
        val dataA = ByteArray(size) { (it % 127).toByte() }
        val dataB = ByteArray(size) { ((it + 42) % 127).toByte() }

        val sealedA = QVaultEngine.sealPayload(dataA, "file", "vaultA.bin", mkA)
        val sealedB = QVaultEngine.sealPayload(dataB, "file", "vaultB.bin", mkB)

        fun parseVault(raw: ByteArray): Pair<ByteArray, List<ByteArray>> {
            val nl = raw.indexOf('\n'.code.toByte())
            val hdrBytes = raw.copyOfRange(0, nl)
            val rest = raw.copyOfRange(nl + 1, raw.size)
            val chunks = mutableListOf<ByteArray>()
            var off = 0
            while (off < rest.size) {
                val len = ByteBuffer.wrap(rest, off, 4).int
                off += 4
                chunks.add(rest.copyOfRange(off, off + len))
                off += len
            }
            return Pair(hdrBytes, chunks)
        }

        fun assembleVault(hdrBytes: ByteArray, chunks: List<ByteArray>): ByteArray {
            val baos = ByteArrayOutputStream()
            baos.write(hdrBytes)
            baos.write('\n'.code)
            for (c in chunks) {
                baos.write(ByteBuffer.allocate(4).putInt(c.size).array())
                baos.write(c)
            }
            return baos.toByteArray()
        }

        val (hdrBytesA, chunksA) = parseVault(sealedA)
        val (_, chunksB) = parseVault(sealedB)
        assertEquals(3, chunksA.size)
        assertEquals(3, chunksB.size)

        // Case 1: Swap chunk 0 and chunk 1
        val swappedChunks = listOf(chunksA[1], chunksA[0], chunksA[2])
        val tamperedSwap = assembleVault(hdrBytesA, swappedChunks)
        try {
            QVaultEngine.openPayload(tamperedSwap, mkA)
            fail("Swapped chunks must be rejected by AEAD authentication")
        } catch (e: Exception) {
            assertNotNull(e)
        }

        // Case 2: Duplicate chunk 0 (replace chunk 1 with chunk 0)
        val dupChunks = listOf(chunksA[0], chunksA[0], chunksA[2])
        val tamperedDup = assembleVault(hdrBytesA, dupChunks)
        try {
            QVaultEngine.openPayload(tamperedDup, mkA)
            fail("Duplicated chunk must be rejected by AEAD authentication")
        } catch (e: Exception) {
            assertNotNull(e)
        }

        // Case 3: Drop middle chunk (keep chunk 0 and chunk 2, update header chunks=2)
        val hdrObjA = JSONObject(String(hdrBytesA, StandardCharsets.UTF_8))
        hdrObjA.put("chunks", 2)
        val droppedHdrBytes = hdrObjA.toString().toByteArray(StandardCharsets.UTF_8)
        val droppedChunks = listOf(chunksA[0], chunksA[2])
        val tamperedDrop = assembleVault(droppedHdrBytes, droppedChunks)
        try {
            QVaultEngine.openPayload(tamperedDrop, mkA)
            fail("Dropped middle chunk must be rejected by AEAD authentication")
        } catch (e: Exception) {
            assertNotNull(e)
        }

        // Case 4: Cross-vault splice (replace chunk 1 of Vault A with chunk 1 from Vault B)
        val splicedChunks = listOf(chunksA[0], chunksB[1], chunksA[2])
        val tamperedSplice = assembleVault(hdrBytesA, splicedChunks)
        try {
            QVaultEngine.openPayload(tamperedSplice, mkA)
            fail("Cross-vault spliced chunk must be rejected by AEAD authentication")
        } catch (e: Exception) {
            assertNotNull(e)
        }
    }

    @Test
    fun testSaltAndNonceUniquenessAcross200Seals() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val mk = QVaultEngine.masterKey(coef)

        val payload = "Fixed payload to verify nonce and salt uniqueness".toByteArray(StandardCharsets.UTF_8)
        val salts = mutableSetOf<String>()
        val bases = mutableSetOf<String>()

        val iterations = 200
        for (i in 0 until iterations) {
            val sealed = QVaultEngine.sealPayload(payload, "text", null, mk)
            val nl = sealed.indexOf('\n'.code.toByte())
            val hdr = JSONObject(String(sealed.copyOfRange(0, nl), StandardCharsets.UTF_8))

            val salt = hdr.getString("salt")
            val base = hdr.getString("base")

            salts.add(salt)
            bases.add(base)
        }

        assertEquals("All $iterations salts must be distinct", iterations, salts.size)
        assertEquals("All $iterations bases must be distinct", iterations, bases.size)
    }

    @Test
    fun testAny13Of140ReconstructsExactSameKeyPropertyTest() {
        val (card, coef) = QVaultEngine.makeCard()
        val mk = QVaultEngine.masterKey(coef)

        // Build list of all 140 evaluation points (x, y)
        val allPoints = mutableListOf<Pair<Int, Int>>()
        for (s in 1..QVaultEngine.SLIPS) {
            for (c in 1..QVaultEngine.CELLS) {
                val x = QVaultEngine.cellX(s, c)
                val y = QVaultEngine.decCell(card[Pair(s, c)]!!)
                allPoints.add(Pair(x, y))
            }
        }
        assertEquals(140, allPoints.size)

        // Sample 2,000 random subsets of 13 points
        val rng = java.util.Random(1337)
        val iterations = 2000

        for (testIdx in 1..iterations) {
            val shuffled = allPoints.toMutableList()
            for (i in 0 until QVaultEngine.K) {
                val j = i + rng.nextInt(shuffled.size - i)
                val temp = shuffled[i]
                shuffled[i] = shuffled[j]
                shuffled[j] = temp
            }
            val subset = shuffled.take(QVaultEngine.K)
            val pts = subset.toMap()

            val reconstructedCoef = QVaultEngine.interpolate(pts)
            assertEquals("Subset #$testIdx reconstructed mismatched polynomial", coef, reconstructedCoef)

            val reconstructedMk = QVaultEngine.masterKey(reconstructedCoef)
            assertTrue("Subset #$testIdx reconstructed mismatched master key", reconstructedMk.contentEquals(mk))
        }
    }
}
