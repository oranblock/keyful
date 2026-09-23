package com.keyful.app.nfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import net.sf.scuba.smartcards.IsoDepCardService
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ISO9796d2Signer
import org.jmrtd.BACKey
import org.jmrtd.PACEKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.icao.DG15File
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * Reads a Kuwait PACI / ICAO 9303 Civil ID chip the way the chip is designed to be read.
 *
 * The files on these cards are not readable with bare READ BINARY: every such attempt
 * answers 6A82 ("file not found") because the file only exists once secure messaging is
 * running. Access therefore requires PACE (preferred) or BAC, keyed by data printed on
 * the card itself — the CAN, or the document number plus date of birth and date of expiry.
 *
 * Identity comes from DG15, the Active Authentication public key, which is unique per
 * chip. Active Authentication then asks the chip to sign a fresh random challenge with
 * the matching private key, which never leaves the secure element. A card that only
 * replays copied bytes cannot produce that signature, so [ChipIdentity.activeAuthVerified]
 * distinguishes a genuine chip from cloned data.
 */
object CivilIdChipReader {

    private val rng = SecureRandom()

    /** Credentials printed on the physical card, used to open secure messaging. */
    sealed interface AccessKey {
        /** Card Access Number, the short number printed on the card face. */
        data class Can(val can: String) : AccessKey

        /** Document number plus date of birth and date of expiry, each as yyMMdd. */
        data class Mrz(
            val documentNumber: String,
            val dateOfBirth: String,
            val dateOfExpiry: String
        ) : AccessKey
    }

    /**
     * @param chipId stable per-chip identifier: a digest of the DG15 public key.
     * @param activeAuthVerified the chip signed our random challenge with its private key.
     * @param protocol which access protocol actually opened the chip, for diagnostics.
     */
    data class ChipIdentity(
        val chipId: ByteArray,
        val activeAuthVerified: Boolean,
        val protocol: String
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ChipIdentity) return false
            return chipId.contentEquals(other.chipId) &&
                activeAuthVerified == other.activeAuthVerified &&
                protocol == other.protocol
        }

        override fun hashCode(): Int {
            var result = chipId.contentHashCode()
            result = 31 * result + activeAuthVerified.hashCode()
            result = 31 * result + protocol.hashCode()
            return result
        }
    }

    class ChipReadException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * Opens [tag] with [accessKey] and returns its verified identity.
     *
     * @throws ChipReadException with a message meant for the person holding the card.
     */
    fun read(tag: Tag, accessKey: AccessKey): ChipIdentity {
        installFullBouncyCastle()

        val isoDep = IsoDep.get(tag)
            ?: throw ChipReadException("This card is not an ISO 14443-4 smartcard, so it has no chip to read.")

        isoDep.timeout = 15_000

        val cardService = IsoDepCardService(isoDep)
        val service = PassportService(
            cardService,
            PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            false,
            false
        )

        try {
            service.open()

            val paceUsed = tryPace(service, accessKey)
            service.sendSelectApplet(paceUsed)

            val protocol: String
            if (paceUsed) {
                protocol = "PACE"
            } else {
                val bacKey = accessKey.asBacKeyOrNull()
                    ?: throw ChipReadException(
                        "This chip refused PACE with the card access number. Enter the document number, " +
                            "date of birth and date of expiry instead."
                    )
                try {
                    service.doBAC(bacKey)
                } catch (e: Exception) {
                    throw ChipReadException(
                        "The chip rejected these card details. Check the document number, date of birth " +
                            "and date of expiry, then try again.",
                        e
                    )
                }
                protocol = "BAC"
            }

            val publicKey = try {
                service.getInputStream(PassportService.EF_DG15, PassportService.DEFAULT_MAX_BLOCKSIZE).use { input ->
                    DG15File(input).publicKey
                }
            } catch (e: Exception) {
                throw ChipReadException(
                    "This chip does not expose an Active Authentication key (DG15), so it cannot be " +
                        "bound to a vault.",
                    e
                )
            }

            val activeAuthVerified = verifyActiveAuthentication(service, publicKey)

            return ChipIdentity(
                chipId = chipIdOf(publicKey),
                activeAuthVerified = activeAuthVerified,
                protocol = protocol
            )
        } catch (e: ChipReadException) {
            throw e
        } catch (e: Exception) {
            throw ChipReadException(
                "This chip did not accept the standard ePassport commands. Use a passport, " +
                    "not a national ID card.",
                e
            )
        } finally {
            try {
                service.close()
            } catch (_: Exception) {
            }
        }
    }

    @Volatile
    private var bouncyCastleInstalled = false

    /**
     * Replaces Android's cut-down "BC" provider with the full BouncyCastle on the classpath.
     *
     * Secure messaging needs ISO9797Alg3Mac (Retail MAC), which Android's bundled provider
     * does not implement, and JMRTD asks for it by the provider name "BC". The replacement
     * is appended rather than inserted first, so platform crypto keeps using the faster
     * AndroidOpenSSL implementations and only the "BC" name resolves here.
     */
    @Synchronized
    private fun installFullBouncyCastle() {
        if (bouncyCastleInstalled) return
        try {
            java.security.Security.removeProvider(
                org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
            )
            java.security.Security.addProvider(
                org.bouncycastle.jce.provider.BouncyCastleProvider()
            )
            bouncyCastleInstalled = true
        } catch (e: Exception) {
            throw ChipReadException("Could not initialise the cryptography provider.", e)
        }
    }

    /** The chip identity used as key material: a digest of the DG15 public key. */
    fun chipIdOf(publicKey: PublicKey): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("QV5-CHIP-AA-V1".toByteArray(Charsets.UTF_8))
        md.update(publicKey.encoded)
        return md.digest()
    }

    private fun AccessKey.asBacKeyOrNull(): BACKey? = when (this) {
        is AccessKey.Mrz -> BACKey(documentNumber, dateOfBirth, dateOfExpiry)
        is AccessKey.Can -> null
    }

    /**
     * Attempts PACE using the parameters the chip advertises in EF.CardAccess.
     * Returns false when the chip offers no usable PACE parameters, so the caller falls back to BAC.
     */
    private fun tryPace(service: PassportService, accessKey: AccessKey): Boolean {
        val paceInfos: List<PACEInfo> = try {
            service.getInputStream(PassportService.EF_CARD_ACCESS, PassportService.DEFAULT_MAX_BLOCKSIZE).use { input ->
                CardAccessFile(input).securityInfos.filterIsInstance<PACEInfo>()
            }
        } catch (_: Exception) {
            // No EF.CardAccess means a BAC-only chip.
            return false
        }

        if (paceInfos.isEmpty()) return false

        val keySpec = try {
            when (accessKey) {
                is AccessKey.Can -> PACEKeySpec.createCANKey(accessKey.can)
                is AccessKey.Mrz -> PACEKeySpec.createMRZKey(
                    BACKey(accessKey.documentNumber, accessKey.dateOfBirth, accessKey.dateOfExpiry)
                )
            }
        } catch (_: Exception) {
            return false
        }

        for (paceInfo in paceInfos) {
            try {
                service.doPACE(
                    keySpec,
                    paceInfo.objectIdentifier,
                    PACEInfo.toParameterSpec(paceInfo.parameterId),
                    null
                )
                return true
            } catch (_: Exception) {
                // Try the next advertised parameter set.
            }
        }
        return false
    }

    /**
     * Asks the chip to sign a fresh random challenge and checks the signature against DG15.
     *
     * A chip that cannot do this is either not running Active Authentication or is not the
     * chip the DG15 key belongs to.
     */
    private fun verifyActiveAuthentication(service: PassportService, publicKey: PublicKey): Boolean {
        val challenge = ByteArray(8)
        rng.nextBytes(challenge)

        return try {
            when (publicKey) {
                is RSAPublicKey -> {
                    val result = service.doAA(publicKey, "SHA-1", "SHA1WithRSA/ISO9796-2", challenge)
                    verifyIso9796d2(publicKey, challenge, result.response)
                }
                is ECPublicKey -> {
                    val result = service.doAA(publicKey, "SHA-256", "SHA256withECDSA", challenge)
                    Signature.getInstance("SHA256withECDSA").run {
                        initVerify(publicKey)
                        update(challenge)
                        verify(result.response)
                    }
                }
                else -> false
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * ICAO 9303 Active Authentication with an RSA key is an ISO 9796-2 scheme 1 signature
     * with partial message recovery: the chip's own nonce is recovered from the signature
     * and our challenge is appended as the non-recovered part.
     */
    private fun verifyIso9796d2(
        publicKey: RSAPublicKey,
        challenge: ByteArray,
        response: ByteArray
    ): Boolean {
        for (digest in listOf(SHA1Digest(), SHA256Digest())) {
            try {
                val signer = ISO9796d2Signer(RSAEngine(), digest, true)
                signer.init(false, RSAKeyParameters(false, publicKey.modulus, publicKey.publicExponent))
                signer.updateWithRecoveredMessage(response)
                signer.update(challenge, 0, challenge.size)
                if (signer.verifySignature(response)) return true
            } catch (_: Exception) {
                // Try the next digest the chip may have used.
            }
        }
        return false
    }
}
