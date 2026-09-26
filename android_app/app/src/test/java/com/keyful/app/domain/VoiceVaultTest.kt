package com.keyful.app.domain

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.util.Random

class VoiceVaultTest {

    companion object {
        private val card = QVaultEngine.cardFromCoef(QVaultEngine.makeCard().second)
        private val secret = "QV6/QV7 secret: cells + voice (+ passphrase)".toByteArray(StandardCharsets.UTF_8)
        private val pass = "correct horse battery staple".toCharArray()
        private val voice = voice(11)
        private lateinit var qv7: ByteArray
        private lateinit var qv6: ByteArray

        private fun voice(seed: Long) = Random(seed).let { r -> FloatArray(128) { r.nextGaussian().toFloat() } }

        @BeforeClass @JvmStatic
        fun sealOnce() {
            qv7 = VoiceVault.seal(secret, "text", null, card, VoiceVault.QV7, 3, voice, pass)
            qv6 = VoiceVault.seal(secret, "text", null, card, VoiceVault.QV6, 3, voice, CharArray(0))
        }
    }

    private val passportA = ByteArray(32) { (it * 7 + 1).toByte() }
    private val passportB = ByteArray(32) { (it * 11 + 3).toByte() }

    private fun cellsFor(p: VoiceVault.Parsed, lock: Int) = VoiceVault.challenge(p, lock).map { card.cells[it]!! }
    private fun cellSecret(p: VoiceVault.Parsed, lock: Int) = VoiceVault.openCells(p, lock, cellsFor(p, lock))!!
    private fun opposite(v: FloatArray) = FloatArray(v.size) { -v[it] }

    @Test fun qv7OpensWithCellsVoiceAndPassphrase() {
        val p = VoiceVault.parse(qv7)!!
        assertEquals(VoiceVault.QV7, p.magic)
        assertTrue(p.withPass)
        assertEquals(3, p.cells)
        assertNull("the header must not say which card opens it", p.cardFp)
        val o = VoiceVault.open(qv7, p, cellSecret(p, 5), voice, pass)
        assertNotNull(o)
        assertArrayEquals(secret, o!!.payload)
        assertEquals("text", o.meta.getString("type"))
    }

    @Test fun everyCellLockAsksDistinctCellsAndOpensWithTheCard() {
        val p = VoiceVault.parse(qv7)!!
        assertEquals(VoiceVault.CELL_LOCKS, p.cellLocks.size)
        val first = cellSecret(p, 0)
        for (i in p.cellLocks.indices) {
            val coords = VoiceVault.challenge(p, i)
            assertEquals(3, coords.toSet().size)
            coords.forEach { (s, c) -> assertTrue(s in 1..QVaultEngine.SLIPS && c in 1..QVaultEngine.CELLS) }
            assertArrayEquals("lock $i must give the same cell secret", first, cellSecret(p, i))
        }
    }

    @Test fun oneWrongCellStaysShut() {
        val p = VoiceVault.parse(qv7)!!
        val typed = cellsFor(p, 2).toMutableList()
        typed[1] = if (typed[1] == "AAAA") "AAAB" else "AAAA"
        assertNull(VoiceVault.openCells(p, 2, typed))
    }

    @Test fun cellsOfAnotherLockStayShut() {
        val p = VoiceVault.parse(qv7)!!
        assertNull(VoiceVault.openCells(p, 4, cellsFor(p, 3)))
    }

    @Test fun wrongPassphraseStaysShut() {
        val p = VoiceVault.parse(qv7)!!
        assertNull(VoiceVault.open(qv7, p, cellSecret(p, 1), voice, "wrong passphrase".toCharArray()))
    }

    @Test fun otherVoiceStaysShut() {
        val p = VoiceVault.parse(qv7)!!
        assertNull(VoiceVault.open(qv7, p, cellSecret(p, 1), opposite(voice), pass))
    }

    @Test fun sameVoiceWithDayToDayNoiseOpens() {
        val p = VoiceVault.parse(qv7)!!
        val r = Random(7)
        val noisy = FloatArray(voice.size) { voice[it] + (r.nextGaussian() * 0.25).toFloat() }
        assertNotNull(VoiceVault.open(qv7, p, cellSecret(p, 1), noisy, pass))
    }

    @Test fun voiceLockIsBoundToTheCellSecret() {
        val p = VoiceVault.parse(qv7)!!
        assertNull(VoiceVault.open(qv7, p, ByteArray(32), voice, pass))
    }

    @Test fun qv6OpensWithCellsAndVoiceOnly() {
        val p = VoiceVault.parse(qv6)!!
        assertEquals(VoiceVault.QV6, p.magic)
        assertFalse(p.withPass)
        val o = VoiceVault.open(qv6, p, cellSecret(p, 0), voice, CharArray(0))
        assertNotNull(o)
        assertArrayEquals(secret, o!!.payload)
    }

    @Test fun qv6StillNeedsTheVoice() {
        val p = VoiceVault.parse(qv6)!!
        assertNull(VoiceVault.open(qv6, p, cellSecret(p, 0), opposite(voice), CharArray(0)))
    }

    @Test fun relabelingQv7AsQv6DoesNotSkipThePassphrase() {
        val text = String(qv7, StandardCharsets.ISO_8859_1)
        val forged = text.replaceFirst("\"magic\":\"QV7\"", "\"magic\":\"QV6\"").toByteArray(StandardCharsets.ISO_8859_1)
        assertFalse(forged.contentEquals(qv7))
        val p = VoiceVault.parse(forged)!!
        assertEquals(VoiceVault.QV6, p.magic)
        assertNull(VoiceVault.open(forged, p, cellSecret(p, 0), voice, CharArray(0)))
    }

    @Test fun tamperedPayloadIsRejected() {
        val bad = qv7.copyOf()
        bad[bad.size - 3] = (bad[bad.size - 3].toInt() xor 1).toByte()
        val p = VoiceVault.parse(bad)!!
        val cs = cellSecret(p, 0)
        assertThrows(Exception::class.java) { VoiceVault.open(bad, p, cs, voice, pass) }
    }

    @Test fun passportVaultNeedsTheSamePassport() {
        val v = VoiceVault.seal(secret, "text", null, card, VoiceVault.QV7, 3, voice, pass, passportA)
        val p = VoiceVault.parse(v)!!
        assertTrue(p.withPassport)
        assertTrue(VoiceVault.passportMatches(p, passportA))
        assertFalse(VoiceVault.passportMatches(p, passportB))
        val cs = cellSecret(p, 0)
        val o = VoiceVault.open(v, p, cs, voice, pass, passportA)
        assertNotNull(o)
        assertArrayEquals(secret, o!!.payload)
        assertNull(VoiceVault.open(v, p, cs, voice, pass, passportB))
        assertNull(VoiceVault.open(v, p, cs, voice, pass, null))
    }

    @Test fun strippingThePassportFlagDoesNotSkipThePassport() {
        val v = VoiceVault.seal(secret, "text", null, card, VoiceVault.QV6, 3, voice, CharArray(0), passportA)
        val text = String(v, StandardCharsets.ISO_8859_1)
        val check = VoiceVault.passportCheck(passportA)
        var stripped = text.replaceFirst(",\"passport\":\"$check\"", "")
        if (stripped == text) stripped = text.replaceFirst("\"passport\":\"$check\",", "")
        val forged = stripped.toByteArray(StandardCharsets.ISO_8859_1)
        assertFalse(forged.contentEquals(v))
        val p = VoiceVault.parse(forged)!!
        assertFalse(p.withPassport)
        assertNull(VoiceVault.open(forged, p, cellSecret(p, 0), voice, CharArray(0)))
    }

    @Test fun vaultsWithoutPassportIgnoreOne() {
        val p = VoiceVault.parse(qv6)!!
        assertFalse(p.withPassport)
        assertNotNull(VoiceVault.open(qv6, p, cellSecret(p, 0), voice, CharArray(0), passportA))
    }

    @Test fun headerCarriesNoCardOrKeyFingerprint() {
        for (v in listOf(qv7, qv6, QVaultEngine.sealPayload(secret, "text", null, QVaultEngine.masterKey(card.coef)))) {
            val nl = v.indexOf('\n'.code.toByte())
            val hdr = org.json.JSONObject(String(v, 0, nl, StandardCharsets.UTF_8))
            assertFalse("card fingerprint in header", hdr.has("card"))
            assertFalse("key fingerprint in header", hdr.has("key"))
        }
    }

    @Test fun sealVerifiedHandsOutOnlyAVaultThatOpens() {
        val v = VoiceVault.sealVerified(secret, "file", "a.txt", card, VoiceVault.QV7, 4, voice, pass, passportA)
        val p = VoiceVault.parse(v)!!
        val o = VoiceVault.open(v, p, cellSecret(p, 3), voice, pass, passportA)
        assertNotNull(o)
        assertArrayEquals(secret, o!!.payload)
        assertEquals("a.txt", o.meta.getString("name"))
    }

    @Test fun qv5FilesAreNotVoiceVaults() {
        val qv5 = QVaultEngine.sealPayload(secret, "text", null, QVaultEngine.masterKey(card.coef))
        assertNull(VoiceVault.parse(qv5))
    }

    @Test fun thirteenCellsWorkAndOutOfRangeIsRejected() {
        val v13 = VoiceVault.seal(secret, "file", "notes.txt", card, VoiceVault.QV6, 13, voice, CharArray(0))
        val p = VoiceVault.parse(v13)!!
        assertEquals(13, p.cells)
        val o = VoiceVault.open(v13, p, cellSecret(p, 9), voice, CharArray(0))
        assertNotNull(o)
        assertEquals("notes.txt", o!!.meta.getString("name"))
        assertThrows(IllegalArgumentException::class.java) {
            VoiceVault.seal(secret, "text", null, card, VoiceVault.QV6, 2, voice, CharArray(0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            VoiceVault.seal(secret, "text", null, card, VoiceVault.QV6, 14, voice, CharArray(0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            VoiceVault.seal(secret, "text", null, card, VoiceVault.QV7, 3, voice, CharArray(0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            VoiceVault.seal(secret, "text", null, card, VoiceVault.QV6, 3, voice, CharArray(0), ByteArray(31))
        }
    }
}
