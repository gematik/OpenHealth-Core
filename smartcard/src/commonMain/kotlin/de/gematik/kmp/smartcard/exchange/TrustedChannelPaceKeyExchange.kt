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

package de.gematik.kmp.smartcard.exchange

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.gematik.kmp.asn1.Asn1Decoder
import de.gematik.kmp.asn1.Asn1Encoder
import de.gematik.kmp.asn1.Asn1Tag
import de.gematik.kmp.asn1.writeObjectIdentifier
import de.gematik.kmp.asn1.writeTaggedObject
import de.gematik.kmp.crypto.CmacAlgorithm
import de.gematik.kmp.crypto.CmacSpec
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.UnoptimizedCryptoApi
import de.gematik.kmp.crypto.UnsafeCryptoApi
import de.gematik.kmp.crypto.bytes
import de.gematik.kmp.crypto.cipher.AesEcbSpec
import de.gematik.kmp.crypto.cipher.createDecipher
import de.gematik.kmp.crypto.createCmac
import de.gematik.kmp.crypto.key.EcKeyPairSpec
import de.gematik.kmp.crypto.key.EcPoint
import de.gematik.kmp.crypto.key.EcPrivateKey
import de.gematik.kmp.crypto.key.EcPublicKey
import de.gematik.kmp.crypto.key.SecretKey
import de.gematik.kmp.crypto.key.decodeFromUncompressedFormat
import de.gematik.kmp.crypto.key.generateKeyPair
import de.gematik.kmp.crypto.key.toEcPoint
import de.gematik.kmp.crypto.key.toEcPublicKey
import de.gematik.kmp.crypto.secureRandom
import de.gematik.kmp.smartcard.card.CardKey
import de.gematik.kmp.smartcard.card.Mode
import de.gematik.kmp.smartcard.card.PaceKey
import de.gematik.kmp.smartcard.card.getAES128Key
import de.gematik.kmp.smartcard.card.isEGK21
import de.gematik.kmp.smartcard.card.parseHealthCardVersion2
import de.gematik.kmp.smartcard.cardobjects.Ef
import de.gematik.kmp.smartcard.command.HealthCardCommand
import de.gematik.kmp.smartcard.command.executeSuccessfulOn
import de.gematik.kmp.smartcard.command.generalAuthenticate
import de.gematik.kmp.smartcard.command.manageSecEnvWithoutCurves
import de.gematik.kmp.smartcard.command.read
import de.gematik.kmp.smartcard.command.select
import de.gematik.kmp.smartcard.identifier.FileIdentifier
import de.gematik.kmp.smartcard.identifier.ShortFileIdentifier

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
@OptIn(
    ExperimentalCryptoApi::class,
    UnsafeCryptoApi::class,
    ExperimentalStdlibApi::class,
    UnoptimizedCryptoApi::class,
)
suspend fun ICardChannel.establishTrustedChannel(cardAccessNumber: String): PaceKey {
    val random = secureRandom()

    // Helper to derive AES keys
    suspend fun deriveAESKey(
        sharedSecret: ByteArray,
        mode: Mode,
    ): SecretKey {
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
    suspend fun performKeyExchange(paceInfo: PaceInfo): Pair<EcPoint, EcPrivateKey> {
        val nonceZ =
            parseAsn1KeyObject(
                HealthCardCommand
                    .generalAuthenticate(true)
                    .executeSuccessfulOn(this)
                    .apdu.data,
            )
        val canKey = deriveAESKey(cardAccessNumber.encodeToByteArray(), de.gematik.kmp.smartcard.card.Mode.PASSWORD)
        val nonceS =
            AesEcbSpec(16.bytes, autoPadding = false)
                .createDecipher(canKey)
                .let {
                    BigInteger.fromByteArray(it.update(nonceZ), Sign.POSITIVE)
                }

        val (_, pcdPrivateKey) = EcKeyPairSpec(paceInfo.curve).generateKeyPair()
        val pcdSharedSecret = paceInfo.curve.g * pcdPrivateKey.s

        val piccPublicKey =
            EcPublicKey.decodeFromUncompressedFormat(
                paceInfo.curve,
                parseAsn1KeyObject(
                    HealthCardCommand
                        .generalAuthenticate(true, pcdSharedSecret.uncompressed, 1)
                        .executeSuccessfulOn(this)
                        .apdu.data,
                ),
            )

        val (_, epPrivateKey) = EcKeyPairSpec(paceInfo.curve).generateKeyPair()
        val epSharedSecret = piccPublicKey.toEcPoint() * pcdPrivateKey.s

        val gsSharedSecret = paceInfo.curve.g * nonceS + epSharedSecret

        val epGsSharedSecret = gsSharedSecret * epPrivateKey.s

        return Pair(epGsSharedSecret, epPrivateKey)
    }

    // Step 3: Mutual Authentication
    suspend fun performMutualAuthentication(
        paceInfo: PaceInfo,
        epGsSharedSecret: EcPoint,
        epPrivateKey: EcPrivateKey,
    ): PaceKey {
        val piccPublicKey =
            EcPublicKey.decodeFromUncompressedFormat(
                paceInfo.curve,
                parseAsn1KeyObject(
                    HealthCardCommand
                        .generalAuthenticate(true, epGsSharedSecret.uncompressed, 3)
                        .executeSuccessfulOn(this)
                        .apdu.data,
                ),
            )

        val sharedSecret = piccPublicKey.toEcPoint() * epPrivateKey.s
        val sharedSecretX =
            sharedSecret.x!!.toByteArray().let {
                // integer might be padded with 0 to make it positive; we don't require this here
                if (it[0] == 0x00.toByte()) it.copyOfRange(1, it.size) else it
            }

        val encryptionKey = deriveAESKey(sharedSecretX, de.gematik.kmp.smartcard.card.Mode.ENC)
        val macKey = deriveAESKey(sharedSecretX, de.gematik.kmp.smartcard.card.Mode.MAC)
        val paceKey = PaceKey(encryptionKey, macKey)

        val mac = deriveMac(paceKey.mac, piccPublicKey, paceInfo.protocolId)
        val derivedMac =
            deriveMac(paceKey.mac, epGsSharedSecret.toEcPublicKey(), paceInfo.protocolId)

        println("derivedMac ${derivedMac.toHexString()} ${derivedMac.asList()}")
        println("mac ${mac.toHexString()}")

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
    val (epGsSharedSecret, epPrivateKey) = performKeyExchange(paceInfo)
    return performMutualAuthentication(paceInfo, epGsSharedSecret, epPrivateKey)
}

fun parseAsn1KeyObject(asn1: ByteArray): ByteArray =
    Asn1Decoder(asn1).read {
        advanceWithTag(28, Asn1Tag.APPLICATION or Asn1Tag.CONSTRUCTED) {
            readTag()
            readBytes(readLength())
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
        it.final().copyOfRange(0, 8)
    }
}

// Create ASN.1 Authentication Token
@OptIn(ExperimentalCryptoApi::class)
fun createAsn1AuthToken(
    publicKey: EcPublicKey,
    protocolId: String,
): ByteArray =
    Asn1Encoder().write {
        writeTaggedObject(0x49, Asn1Tag.APPLICATION or Asn1Tag.CONSTRUCTED) {
            writeObjectIdentifier(protocolId)
            writeTaggedObject(0x06, Asn1Tag.CONTEXT_SPECIFIC) {
                write(publicKey.data)
            }
        }
    }