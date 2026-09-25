package com.keyful.app.voicelab

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Random

class VoiceLockTest {
    private val secret = "shamir coefficients go here".toByteArray()
    private val pass = "correct horse battery staple".toCharArray()

    private fun voice(seed: Long) = Random(seed).let { r -> FloatArray(128) { r.nextGaussian().toFloat() } }
    private fun noisy(v: FloatArray, sd: Double, seed: Long) =
        Random(seed).let { r -> FloatArray(v.size) { v[it] + (r.nextGaussian() * sd).toFloat() } }

    @Test fun sameVoiceAndPassphraseOpens() {
        val v = voice(1)
        val blob = VoiceLock.sealBytes(pass, v, secret)
        val o = VoiceLock.openBytes(pass, v, blob)
        assertNotNull(o); assertArrayEquals(secret, o!!.secret)
    }

    @Test fun sameVoiceWithDayToDayNoiseStillOpens() {
        val v = voice(2)
        val blob = VoiceLock.sealBytes(pass, v, secret)
        val o = VoiceLock.openBytes(pass, noisy(v, 0.25, 99), blob)
        assertNotNull("a slightly different take of the same voice must open", o)
        assertArrayEquals(secret, o!!.secret)
    }

    @Test fun wrongPassphraseStaysShutEvenWithRightVoice() {
        val v = voice(3)
        val blob = VoiceLock.sealBytes(pass, v, secret)
        assertNull(VoiceLock.openBytes("wrong passphrase".toCharArray(), v, blob))
    }

    @Test fun oppositeVoiceStaysShutEvenWithRightPassphrase() {
        val v = voice(4)
        val blob = VoiceLock.sealBytes(pass, v, secret)
        val other = FloatArray(v.size) { -v[it] }          // every voice bit different
        assertNull(VoiceLock.openBytes(pass, other, blob))
    }

    @Test fun tamperedFileStaysShut() {
        val v = voice(5)
        val blob = VoiceLock.sealBytes(pass, v, secret)
        blob[blob.size - 5] = (blob[blob.size - 5].toInt() xor 0x01).toByte()
        assertNull(VoiceLock.openBytes(pass, v, blob))
    }

    @Test fun boundLockNeedsTheBindSecret() {
        val v = voice(7)
        val bind = ByteArray(32) { it.toByte() }
        val blob = VoiceLock.sealBytes(pass, v, secret, bind)
        assertNotNull(VoiceLock.openBytes(pass, v, blob, bind))
        assertNull(VoiceLock.openBytes(pass, v, blob))
        assertNull(VoiceLock.openBytes(pass, v, blob, ByteArray(32)))
    }

    @Test fun emptyPassphraseMeansVoiceOnly() {
        val v = voice(8)
        val blob = VoiceLock.sealBytes(CharArray(0), v, secret)
        assertNotNull(VoiceLock.openBytes(CharArray(0), v, blob))
        assertNull(VoiceLock.openBytes("anything".toCharArray(), v, blob))
    }

    @Test fun fileDoesNotContainTheVoiceprint() {
        val v = voice(6)
        val blob = VoiceLock.sealBytes(pass, v, secret)
        val buf = java.nio.ByteBuffer.allocate(4)
        for (x in v.take(16)) {
            buf.clear(); buf.putFloat(x)
            val pat = buf.array()
            val found = (0..blob.size - 4).any { i -> (0 until 4).all { blob[i + it] == pat[it] } }
            assertFalse("voiceprint value leaked into the file", found)
        }
    }
}
