@file:Suppress("MagicNumber")

package de.gematik.ti.healthcard.model.exchange

import de.gematik.ti.healthcard.model.CardUtilities.byteArrayToECPoint
import de.gematik.ti.healthcard.model.CardUtilities.extractKeyObjectEncoded
import de.gematik.ti.healthcard.model.card.CardKey
import de.gematik.ti.healthcard.model.card.HealthCardVersion2
import de.gematik.ti.healthcard.model.card.ICardChannel
import de.gematik.ti.healthcard.model.card.PaceKey
import de.gematik.ti.healthcard.model.card.isEGK21
import de.gematik.ti.healthcard.model.cardobjects.Ef
import de.gematik.ti.healthcard.model.command.HealthCardCommand
import de.gematik.ti.healthcard.model.command.executeSuccessfulOn
import de.gematik.ti.healthcard.model.command.generalAuthenticate
import de.gematik.ti.healthcard.model.command.manageSecEnvWithoutCurves
import de.gematik.ti.healthcard.model.command.read
import de.gematik.ti.healthcard.model.command.select
import de.gematik.ti.healthcard.model.identifier.FileIdentifier
import de.gematik.ti.healthcard.model.identifier.ShortFileIdentifier

private const val SECRET_KEY_REFERENCE = 2 // Reference of secret key for PACE (CAN)
private const val AES_BLOCK_SIZE = 16
private const val BYTE_LENGTH = 8
private const val MAX = 64
private const val TAG_6 = 6
private const val TAG_49 = 0x49

/**
 * Opens a secure PACE Channel for secure messaging
 *
 * picc = card
 * pcd = smartphone
 */
suspend fun ICardChannel.establishTrustedChannel(cardAccessNumber: String): PaceKey {
    val random = SecureRandom()

    // Helper to derive AES keys
    fun deriveAESKey(input: ByteArray): SecretKeySpec = SecretKeySpec(input.copyOf(16), "AES")

    // Step 1: Read and configure supported PACE parameters
    suspend fun initializePace(): PaceInfo {
        HealthCardCommand
            .select(
                selectParentElseRoot = false,
                readFirst = true,
            ).executeSuccessfulOn(this)
        HealthCardCommand
            .read(
                ShortFileIdentifier(Ef.Version2.SFID),
                0,
            ).executeSuccessfulOn(this)
            .let {
                check(HealthCardVersion2.of(it.apdu.data).isEGK21()) { "Invalid eGK Version." }
            }

        HealthCardCommand.select(FileIdentifier(Ef.CardAccess.FID), false).executeSuccessfulOn(this)
        val paceInfo =
            PaceInfo(
                HealthCardCommand
                    .read()
                    .executeOn(this)
                    .apdu.data,
            )

        HealthCardCommand
            .manageSecEnvWithoutCurves(
                CardKey(SECRET_KEY_REFERENCE),
                false,
                paceInfo.paceInfoProtocolBytes,
            ).executeSuccessfulOn(this)

        return paceInfo
    }

    // Step 2: Perform Ephemeral Key Exchange
    suspend fun performKeyExchange(paceInfo: PaceInfo): Pair<SecretKeySpec, ByteArray> {
        val nonceZ =
            extractKeyObjectEncoded(
                HealthCardCommand
                    .generalAuthenticate(true)
                    .executeSuccessfulOn(this)
                    .apdu.data,
            )
        val canKey = deriveAESKey(cardAccessNumber.toByteArray())
        val nonceS =
            Cipher
                .getInstance("AES/ECB/NoPadding")
                .apply {
                    init(Cipher.DECRYPT_MODE, canKey)
                }.doFinal(nonceZ)

        val ecKeyPair = generateEphemeralKeyPair(paceInfo.ecCurve)
        val privateKey = ecKeyPair.first
        val publicKey = ecKeyPair.second

        val piccPublicKey =
            byteArrayToECPoint(
                extractKeyObjectEncoded(
                    HealthCardCommand
                        .generalAuthenticate(true, publicKey, 1)
                        .executeSuccessfulOn(this)
                        .apdu.data,
                ),
                paceInfo.ecCurve,
            )

        val keyAgreement = computeSharedSecret(privateKey, piccPublicKey, paceInfo.ecCurve)

        return Pair(deriveAESKey(keyAgreement), publicKey)
    }

    // Step 3: Mutual Authentication
    suspend fun performMutualAuthentication(
        paceKey: SecretKeySpec,
        publicKey: ByteArray,
        paceInfo: PaceInfo,
    ): PaceKey {
        val piccPublicKey =
            extractKeyObjectEncoded(
                HealthCardCommand
                    .generalAuthenticate(true, publicKey, 3)
                    .executeSuccessfulOn(this)
                    .apdu.data,
            )
        val derivedMac = deriveMac(paceKey, piccPublicKey, paceInfo.protocolID)
        val mac = deriveMac(paceKey, publicKey, paceInfo.protocolID)

        val piccMac =
            extractKeyObjectEncoded(
                HealthCardCommand
                    .generalAuthenticate(false, mac, 5)
                    .executeSuccessfulOn(this)
                    .apdu.data,
            )
        check(piccMac.contentEquals(derivedMac)) { "Mutual authentication failed." }

        return PaceKey(paceKey, paceKey)
    }

    // Main PACE negotiation flow
    val paceInfo = initializePace()
    val (paceKey, publicKey) = performKeyExchange(paceInfo)
    return performMutualAuthentication(paceKey, publicKey, paceInfo)
}

// Generate an ephemeral EC key pair
fun generateEphemeralKeyPair(curve: ECCurve): Pair<ECPrivateKey, ByteArray> {
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    keyPairGenerator.initialize(curve.spec)
    val keyPair = keyPairGenerator.generateKeyPair()
    val privateKey = (keyPair.private as ECPrivateKey).s
    val publicKey = (keyPair.public as ECPublicKey).q.encoded(false)
    return Pair(privateKey, publicKey)
}

// Compute shared secret using ECDH
fun computeSharedSecret(
    privateKey: ECPrivateKey,
    publicKey: ECPoint,
    curve: ECCurve,
): ByteArray {
    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(privateKey)
    keyAgreement.doPhase(ECPublicKey(publicKey, curve.spec), true)
    return keyAgreement.generateSecret()
}

// Derive MAC from a key
fun deriveMac(
    key: SecretKeySpec,
    publicKey: ByteArray,
    protocolID: String,
): ByteArray {
    val mac = Mac.getInstance("AESCMAC").apply { init(key) }
    val authToken = createAsn1AuthToken(publicKey, protocolID)
    return mac.doFinal(authToken)
}

// Create ASN.1 Authentication Token
fun createAsn1AuthToken(
    ecPoint: ByteArray,
    protocolID: String,
): ByteArray {
    val asn1EncodableVector =
        ASN1EncodableVector().apply {
            add(ASN1ObjectIdentifier(protocolID))
            add(DEROctetString(ecPoint))
        }
    return DERSequence(asn1EncodableVector).encoded
}