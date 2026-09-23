package com.keyful.app.domain

import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

class EphemeralHandshakeEngineTest {

    private val rng = SecureRandom()

    private fun sha256Hex(data: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }

    @Test
    fun testFullHandshakeRoundTrip() {
        // 1. Generate master card & vault
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)
        val expectedMasterKey = QVaultEngine.masterKey(coef)

        val plaintext = "Encrypted Vault Message via Zero-Input Ephemeral Handshake!".toByteArray(StandardCharsets.UTF_8)
        val sealedVault = QVaultEngine.sealPayload(plaintext, "text", null, expectedMasterKey, cFp)

        // 2. Verifier (Vault App) generates Ephemeral Challenge
        val (challenge, verifierPriv) = EphemeralHandshakeEngine.createChallenge(vaultFp = cFp)
        val serializedChallenge = challenge.serialize()
        assertTrue(serializedChallenge.startsWith(EphemeralHandshakeEngine.CHALLENGE_PREFIX))

        // Parse challenge on Prover side (simulate QR scan or IPC transfer)
        val parsedChallenge = EphemeralHandshakeEngine.ChallengeEnvelope.parse(serializedChallenge)
        assertEquals(challenge.version, parsedChallenge.version)
        assertArrayEquals(challenge.nonce, parsedChallenge.nonce)
        assertEquals(cFp, parsedChallenge.vaultFp)

        // 3. Prover (Keyholder / Civil ID App) creates Ephemeral Response
        val response = EphemeralHandshakeEngine.createResponse(parsedChallenge, coef)
        val serializedResponse = response.serialize()
        assertTrue(serializedResponse.startsWith(EphemeralHandshakeEngine.RESPONSE_PREFIX))

        // Parse response on Verifier side (simulate camera scan or IPC return)
        val parsedResponse = EphemeralHandshakeEngine.ResponseEnvelope.parse(serializedResponse)
        assertEquals(response.version, parsedResponse.version)
        assertArrayEquals(response.iv, parsedResponse.iv)

        // 4. Verifier processes response & reconstructs Master Key
        val recoveredMasterKey = EphemeralHandshakeEngine.processResponse(parsedResponse, challenge, verifierPriv)
        assertArrayEquals(expectedMasterKey, recoveredMasterKey)

        // 5. Open vault with recovered key
        val (meta, decryptedPayload) = QVaultEngine.openPayload(sealedVault, recoveredMasterKey)
        assertEquals("text", meta.getString("type"))
        assertEquals(String(plaintext, StandardCharsets.UTF_8), String(decryptedPayload, StandardCharsets.UTF_8))
    }

    @Test
    fun testEphemeralRandomnessPropertyAcross50Handshakes() {
        val (_, coef) = QVaultEngine.makeCard()
        val expectedMasterKey = QVaultEngine.masterKey(coef)

        val pubKeys = mutableSetOf<String>()
        val ivs = mutableSetOf<String>()
        val ciphertexts = mutableSetOf<String>()
        val payloadSizes = mutableSetOf<Int>()

        for (i in 1..50) {
            val (challenge, verifierPriv) = EphemeralHandshakeEngine.createChallenge()
            val response = EphemeralHandshakeEngine.createResponse(challenge, coef)

            val pubHex = response.proverPubBytes.joinToString("") { "%02x".format(it) }
            val ivHex = response.iv.joinToString("") { "%02x".format(it) }
            val ctHex = response.ciphertext.joinToString("") { "%02x".format(it) }

            pubKeys.add(pubHex)
            ivs.add(ivHex)
            ciphertexts.add(ctHex)
            payloadSizes.add(response.ciphertext.size)

            val recoveredKey = EphemeralHandshakeEngine.processResponse(response, challenge, verifierPriv)
            assertArrayEquals("Failed on iteration $i", expectedMasterKey, recoveredKey)
        }

        // Invariant: 50/50 distinct ephemeral public keys, IVs, and ciphertexts
        assertEquals("Prover public keys must all be distinct", 50, pubKeys.size)
        assertEquals("IVs must all be distinct", 50, ivs.size)
        assertEquals("Ciphertexts must all be distinct", 50, ciphertexts.size)
        // Jitter padding produces variable sizes
        assertTrue("Payload sizes must vary due to random jitter padding", payloadSizes.size > 1)
    }

    @Test
    fun testExpiredChallengeRejected() {
        val (_, coef) = QVaultEngine.makeCard()
        val (validChallenge, _) = EphemeralHandshakeEngine.createChallenge()

        // Create expired challenge (timestamp 2 minutes ago)
        val expiredChallenge = validChallenge.copy(timestampMs = System.currentTimeMillis() - 120_000L)
        assertTrue(expiredChallenge.isExpired())

        assertThrows(IllegalArgumentException::class.java) {
            EphemeralHandshakeEngine.createResponse(expiredChallenge, coef)
        }
    }

    @Test
    fun testMismatchedNonceRejected() {
        val (_, coef) = QVaultEngine.makeCard()
        val (challenge1, verifierPriv1) = EphemeralHandshakeEngine.createChallenge()
        val (challenge2, _) = EphemeralHandshakeEngine.createChallenge()

        // Prover responds to challenge 2
        val response2 = EphemeralHandshakeEngine.createResponse(challenge2, coef)

        // Verifier 1 tries to use response 2 against challenge 1 -> must fail (AEAD auth or nonce mismatch)
        assertThrows(Exception::class.java) {
            EphemeralHandshakeEngine.processResponse(response2, challenge1, verifierPriv1)
        }
    }

    @Test
    fun testCivilIdDeviceSealingRoundTrip() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)

        val civilIdUid = byteArrayOf(0x04.toByte(), 0xA2.toByte(), 0x3B.toByte(), 0x8F.toByte(), 0x11.toByte(), 0x90.toByte(), 0x5C.toByte())
        val deviceUuid = "e3b0c442-98fc-1c14-9afb-4c8996fb9242"
        val passkey = "hardware_backed_user_passkey_99482".toByteArray(StandardCharsets.UTF_8)

        val container = EphemeralHandshakeEngine.sealCardToDevice(coef, civilIdUid, deviceUuid, passkey, cFp)
        val serialized = container.serialize()
        assertTrue(serialized.startsWith("QVSEAL1:"))

        val parsed = EphemeralHandshakeEngine.SealedCardContainer.parse(serialized)
        assertEquals(cFp, parsed.cardFp)

        val unsealedCoef = EphemeralHandshakeEngine.unsealCardFromDevice(parsed, civilIdUid, deviceUuid, passkey)
        assertEquals(coef, unsealedCoef)

        val masterKeyOrig = QVaultEngine.masterKey(coef)
        val masterKeyUnsealed = QVaultEngine.masterKey(unsealedCoef)
        assertArrayEquals(masterKeyOrig, masterKeyUnsealed)
    }

    @Test
    fun testCivilIdDeviceSealingWrongCivilIdCardRejected() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)

        val realCivilIdUid = byteArrayOf(0x04.toByte(), 0xA2.toByte(), 0x3B.toByte(), 0x8F.toByte(), 0x11.toByte(), 0x90.toByte(), 0x5C.toByte())
        val wrongCivilIdUid = byteArrayOf(0x04.toByte(), 0xA2.toByte(), 0x3B.toByte(), 0x8F.toByte(), 0x11.toByte(), 0x90.toByte(), 0x5D.toByte()) // 1 bit altered
        val deviceUuid = "device-uuid-test"
        val passkey = "secret_passkey".toByteArray(StandardCharsets.UTF_8)

        val container = EphemeralHandshakeEngine.sealCardToDevice(coef, realCivilIdUid, deviceUuid, passkey, cFp)

        // Attempting to unseal with wrong Civil ID NFC chip must fail authentication
        assertThrows(Exception::class.java) {
            EphemeralHandshakeEngine.unsealCardFromDevice(container, wrongCivilIdUid, deviceUuid, passkey)
        }
    }

    @Test
    fun testCivilIdDeviceSealingWrongDeviceRejected() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)

        val civilIdUid = byteArrayOf(0x04.toByte(), 0xA2.toByte(), 0x3B.toByte(), 0x8F.toByte())
        val deviceUuidReal = "device-uuid-phone-a"
        val deviceUuidStolen = "device-uuid-phone-b"
        val passkey = "secret_passkey".toByteArray(StandardCharsets.UTF_8)

        val container = EphemeralHandshakeEngine.sealCardToDevice(coef, civilIdUid, deviceUuidReal, passkey, cFp)

        // Attempting to unseal on another device must fail
        assertThrows(Exception::class.java) {
            EphemeralHandshakeEngine.unsealCardFromDevice(container, civilIdUid, deviceUuidStolen, passkey)
        }
    }

    @Test
    fun testCivilIdDeviceSealingWrongPasskeyRejected() {
        val (card, coef) = QVaultEngine.makeCard()
        val cFp = QVaultEngine.cardFp(card)

        val civilIdUid = byteArrayOf(0x04.toByte(), 0xA2.toByte(), 0x3B.toByte(), 0x8F.toByte())
        val deviceUuid = "device-uuid"
        val passkeyReal = "real_fingerprint_passkey".toByteArray(StandardCharsets.UTF_8)
        val passkeyWrong = "wrong_fingerprint_passkey".toByteArray(StandardCharsets.UTF_8)

        val container = EphemeralHandshakeEngine.sealCardToDevice(coef, civilIdUid, deviceUuid, passkeyReal, cFp)

        // Attempting to unseal with wrong passkey must fail
        assertThrows(Exception::class.java) {
            EphemeralHandshakeEngine.unsealCardFromDevice(container, civilIdUid, deviceUuid, passkeyWrong)
        }
    }
}
