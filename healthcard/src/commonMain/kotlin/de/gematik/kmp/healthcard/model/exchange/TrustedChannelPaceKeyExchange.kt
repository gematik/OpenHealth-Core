/*
 * Copyright (c) 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:Suppress("MagicNumber")

package de.gematik.kmp.healthcard.model.exchange

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.gematik.kmp.asn1.Asn1Decoder
import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.Asn1Type
import de.gematik.kmp.asn1.applicationTag
import de.gematik.kmp.asn1.constructedTag
import de.gematik.kmp.asn1.contextSpecificTag
import de.gematik.kmp.asn1.writeObjectIdentifier
import de.gematik.kmp.asn1.writeTaggedObject
import de.gematik.kmp.crypto.Cmac
import de.gematik.kmp.crypto.CmacAlgorithm
import de.gematik.kmp.crypto.CmacSpec
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.UnsafeCryptoApi
import de.gematik.kmp.crypto.bytes
import de.gematik.kmp.crypto.cipher.AesCipherSpec
import de.gematik.kmp.crypto.cipher.AesDecipherSpec
import de.gematik.kmp.crypto.cipher.AesEcbSpec
import de.gematik.kmp.crypto.cipher.createDecipher
import de.gematik.kmp.crypto.createCmac
import de.gematik.kmp.crypto.exchange.EcdhSpec
import de.gematik.kmp.crypto.exchange.createKeyExchange
import de.gematik.kmp.crypto.key.EcCurve
import de.gematik.kmp.crypto.key.EcKeyPairSpec
import de.gematik.kmp.crypto.key.EcPrivateKey
import de.gematik.kmp.crypto.key.EcPublicKey
import de.gematik.kmp.crypto.key.SecretKey
import de.gematik.kmp.crypto.key.decodeFromUncompressedFormat
import de.gematik.kmp.crypto.key.generateKeyPair
import de.gematik.kmp.crypto.secureRandom
import de.gematik.kmp.healthcard.model.card.CardKey
import de.gematik.kmp.healthcard.model.card.ICardChannel
import de.gematik.kmp.healthcard.model.card.Mode
import de.gematik.kmp.healthcard.model.card.PaceKey
import de.gematik.kmp.healthcard.model.card.getAES128Key
import de.gematik.kmp.healthcard.model.card.isEGK21
import de.gematik.kmp.healthcard.model.card.parseHealthCardVersion2
import de.gematik.kmp.healthcard.model.cardobjects.Ef
import de.gematik.kmp.healthcard.model.command.HealthCardCommand
import de.gematik.kmp.healthcard.model.command.executeSuccessfulOn
import de.gematik.kmp.healthcard.model.command.generalAuthenticate
import de.gematik.kmp.healthcard.model.command.manageSecEnvWithoutCurves
import de.gematik.kmp.healthcard.model.command.read
import de.gematik.kmp.healthcard.model.command.select
import de.gematik.kmp.healthcard.model.identifier.FileIdentifier
import de.gematik.kmp.healthcard.model.identifier.ShortFileIdentifier

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
@OptIn(ExperimentalCryptoApi::class, UnsafeCryptoApi::class)
suspend fun ICardChannel.establishTrustedChannel(cardAccessNumber: String): PaceKey {
    val random = secureRandom()

    // Helper to derive AES keys
    suspend fun deriveAESKey(sharedSecret: ByteArray, mode: Mode): SecretKey {
        val keyBytes = getAES128Key(sharedSecret, mode)
        return SecretKey(keyBytes)
    }

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
                check(parseHealthCardVersion2(it.apdu.data).isEGK21()) { "Invalid eGK Version." }
            }

        HealthCardCommand.select(FileIdentifier(Ef.CardAccess.FID), false).executeSuccessfulOn(this)
        val paceInfo =
            parsePaceInfo(
                HealthCardCommand
                    .read()
                    .executeOn(this)
                    .apdu.data,
            )

        HealthCardCommand
            .manageSecEnvWithoutCurves(
                CardKey(SECRET_KEY_REFERENCE),
                false,
                paceInfo.protocolIdBytes,
            ).executeSuccessfulOn(this)

        return paceInfo
    }

    // Step 2: Perform Ephemeral Key Exchange
    suspend fun performKeyExchange(paceInfo: PaceInfo): Pair<PaceKey, EcPublicKey> {
        val nonceZ =
            parseAsn1KeyObject(
                HealthCardCommand
                    .generalAuthenticate(true)
                    .executeSuccessfulOn(this)
                    .apdu.data,
            )
        val canKey = deriveAESKey(cardAccessNumber.encodeToByteArray(), Mode.PASSWORD)
        val nonceS = AesEcbSpec(16.bytes)
            .createDecipher(canKey)
            .let {
                BigInteger.fromByteArray(it.update(nonceZ) + it.final(), Sign.POSITIVE)
            }

        val (ephemeralPublicKey, ephemeralPrivateKey) = EcKeyPairSpec(paceInfo.curve).generateKeyPair()

        val piccPublicKey =
            EcPublicKey.decodeFromUncompressedFormat(
                paceInfo.curve,
                parseAsn1KeyObject(
                    HealthCardCommand
                        .generalAuthenticate(true, ephemeralPublicKey.data, 1)
                        .executeSuccessfulOn(this)
                        .apdu.data
                )
            )

        piccPublicKey.data

        val keyAgreement = computeSharedSecret(ephemeralPrivateKey, piccPublicKey, paceInfo.curve)

        val encryptionKey = deriveAESKey(keyAgreement, Mode.ENC)
        val macKey = deriveAESKey(keyAgreement, Mode.MAC)

        return Pair(PaceKey(encryptionKey, macKey), ephemeralPublicKey)
    }

    // Step 3: Mutual Authentication
    suspend fun performMutualAuthentication(
        paceKey: PaceKey,
        publicKey: EcPublicKey,
        paceInfo: PaceInfo,
    ): PaceKey {
        val piccPublicKey =
            EcPublicKey.decodeFromUncompressedFormat(
                paceInfo.curve,
                parseAsn1KeyObject(
                    HealthCardCommand
                        .generalAuthenticate(true, publicKey.data, 3)
                        .executeSuccessfulOn(this)
                        .apdu.data,
                )
            )
        val derivedMac = deriveMac(paceKey.mac, piccPublicKey, paceInfo.protocolId)
        val mac = deriveMac(paceKey.mac, publicKey, paceInfo.protocolId)

        val piccMac =
            parseAsn1KeyObject(
                HealthCardCommand
                    .generalAuthenticate(false, mac, 5)
                    .executeSuccessfulOn(this)
                    .apdu.data,
            )
        check(piccMac.contentEquals(derivedMac)) { "Mutual authentication failed." }

        return paceKey
    }

    // Main PACE negotiation flow
    val paceInfo = initializePace()
    val (paceKey, publicKey) = performKeyExchange(paceInfo)
    return performMutualAuthentication(paceKey, publicKey, paceInfo)
}

// Compute shared secret using ECDH
@OptIn(ExperimentalCryptoApi::class)
suspend fun computeSharedSecret(
    privateKey: EcPrivateKey,
    publicKey: EcPublicKey,
    curve: EcCurve,
): ByteArray {
    return EcdhSpec(curve).createKeyExchange(privateKey).computeSecret(publicKey)
}

fun parseAsn1KeyObject(asn1: ByteArray): ByteArray {
    return Asn1Decoder(asn1).read {
        advanceWithTag(28.applicationTag().constructedTag()) {
            readTag()
            readBytes(readLength())
        }
    }
}

// Derive MAC from a key
@OptIn(ExperimentalCryptoApi::class)
suspend fun deriveMac(
    key: SecretKey,
    publicKey: EcPublicKey,
    protocolID: String,
): ByteArray {
    val authToken = createAsn1AuthToken(publicKey, protocolID)
    return CmacSpec(CmacAlgorithm.Aes).createCmac(key).let {
        it.update(authToken)
        it.final()
    }
}

// Create ASN.1 Authentication Token
@OptIn(ExperimentalCryptoApi::class)
fun createAsn1AuthToken(
    publicKey: EcPublicKey,
    protocolId: String,
): ByteArray {
    return Asn1Encoder().write {
        writeTaggedObject(0x49) {
            writeObjectIdentifier(protocolId)
            writeTaggedObject(0x06) {
                write(publicKey.data)
            }
        }
    }
}