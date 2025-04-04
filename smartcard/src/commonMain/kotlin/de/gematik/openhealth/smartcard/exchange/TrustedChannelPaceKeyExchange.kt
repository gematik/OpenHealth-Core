/*
 * Copyright 2025 gematik GmbH
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

package de.gematik.openhealth.smartcard.exchange

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.asn1.writeObjectIdentifier
import de.gematik.openhealth.asn1.writeTaggedObject
import de.gematik.openhealth.crypto.CmacAlgorithm
import de.gematik.openhealth.crypto.CmacSpec
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.bytes
import de.gematik.openhealth.crypto.cipher.AesCbcSpec
import de.gematik.openhealth.crypto.key.EcKeyPairSpec
import de.gematik.openhealth.crypto.key.EcPoint
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.EcPublicKey
import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.key.decodeFromUncompressedFormat
import de.gematik.openhealth.crypto.key.generateKeyPair
import de.gematik.openhealth.crypto.key.toEcPoint
import de.gematik.openhealth.crypto.key.toEcPublicKey
import de.gematik.openhealth.crypto.useCrypto
import de.gematik.openhealth.smartcard.card.CardKey
import de.gematik.openhealth.smartcard.card.HealthCardScope
import de.gematik.openhealth.smartcard.card.Mode
import de.gematik.openhealth.smartcard.card.PaceKey
import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.card.TrustedChannelScopeImpl
import de.gematik.openhealth.smartcard.card.getAES128Key
import de.gematik.openhealth.smartcard.card.isHealthCardVersion21
import de.gematik.openhealth.smartcard.card.parseHealthCardVersion2
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.generalAuthenticate
import de.gematik.openhealth.smartcard.command.manageSecEnvWithoutCurves
import de.gematik.openhealth.smartcard.command.read
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.identifier.FileIdentifier
import de.gematik.openhealth.smartcard.identifier.ShortFileIdentifier

private const val SECRET_KEY_REFERENCE = 2 // Reference of secret key for PACE (CAN)

/**
 * Establishes a trusted channel using the PACE protocol as specified in gemSpecObjSys and gemSpecCos.
 *
 * Steps:
 * 1. Read and configure PACE parameters from EF.CardAccess.
 * 2. Perform Ephemeral Key Exchange with the card.
 * 3. Complete Mutual Authentication to establish shared keys.
 *
 * Relevant specifications:
 * - gemSpecObjSys#5.3.2 (PACE protocol and EF.CardAccess).
 * - gemSpec_Cos_3.14.0#14.9.9 (MANAGE SECURITY ENVIRONMENT command).
 * - gemSpec_COS_3.14.0#14.7.2.1 (GENERAL AUTHENTICATE command).
 *
 * @param cardAccessNumber The Card Access Number (CAN) for PACE initialization.
 * @return A trusted channel scope to communicate securely with the card.
 */
@OptIn(
    ExperimentalCryptoApi::class,
    UnsafeCryptoApi::class,
)
suspend fun HealthCardScope.establishTrustedChannel(cardAccessNumber: String): TrustedChannelScope {
    // Step 1: Read and configure supported PACE parameters
    suspend fun initializePace(): PaceInfo {
        HealthCardCommand
            .select(
                selectParentElseRoot = false,
                readFirst = true,
            ).transmitSuccessfully()
        HealthCardCommand
            .read(
                ShortFileIdentifier(Mf.Ef.Version2.SFID),
                0,
            ).transmitSuccessfully()
            .let {
                check(
                    parseHealthCardVersion2(it.apdu.data).isHealthCardVersion21(),
                ) { "Invalid eGK Version." }
            }

        HealthCardCommand.select(FileIdentifier(Mf.Ef.CardAccess.FID), false).transmitSuccessfully()
        val paceInfo =
            parsePaceInfo(
                HealthCardCommand
                    .read()
                    .transmit()
                    .apdu.data,
            )

        HealthCardCommand
            .manageSecEnvWithoutCurves(
                CardKey(SECRET_KEY_REFERENCE),
                false,
                paceInfo.protocolIdBytes,
            ).transmitSuccessfully()

        return paceInfo
    }

    // Step 2: Perform Ephemeral Key Exchange
    suspend fun performKeyExchange(paceInfo: PaceInfo): Pair<EcPoint, EcPrivateKey> {
        val nonceZ =
            parseAsn1KeyObject(
                HealthCardCommand
                    .generalAuthenticate(true)
                    .transmitSuccessfully()
                    .apdu.data,
            )

        // REQ-BEGIN: O.Cryp_3, O.Cryp_4
        // | BSI-eRp-ePA
        // | AES Key-Generation and one time usage
        val canKey = deriveAESKey(cardAccessNumber.encodeToByteArray(), Mode.PASSWORD)
        val nonceS =
            useCrypto {
                AesCbcSpec(16.bytes, iv = byteArrayOf(), autoPadding = false)
                    .createDecipher(canKey)
                    .let {
                        BigInteger.fromByteArray(it.update(nonceZ), Sign.POSITIVE)
                    }
            }

        val (_, pcdPrivateKey) = EcKeyPairSpec(paceInfo.curve).generateKeyPair()
        val pcdSharedSecret = paceInfo.curve.g * pcdPrivateKey.s

        val piccPublicKey =
            EcPublicKey.decodeFromUncompressedFormat(
                paceInfo.curve,
                parseAsn1KeyObject(
                    HealthCardCommand
                        .generalAuthenticate(true, pcdSharedSecret.uncompressed, 1)
                        .transmitSuccessfully()
                        .apdu.data,
                ),
            )

        val (_, epPrivateKey) = EcKeyPairSpec(paceInfo.curve).generateKeyPair()
        val epSharedSecret = piccPublicKey.toEcPoint() * pcdPrivateKey.s

        val gsSharedSecret = paceInfo.curve.g * nonceS + epSharedSecret

        val epGsSharedSecret = gsSharedSecret * epPrivateKey.s

        return Pair(epGsSharedSecret, epPrivateKey)
    }
    // REQ-END: O.Cryp_3, O.Cryp_4

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
                        .transmitSuccessfully()
                        .apdu.data,
                ),
            )

        val sharedSecret = piccPublicKey.toEcPoint() * epPrivateKey.s
        val sharedSecretX = sharedSecret.uncompressed.copyOfRange(1, 33)

        val encryptionKey = deriveAESKey(sharedSecretX, Mode.ENC)
        val macKey = deriveAESKey(sharedSecretX, Mode.MAC)
        val paceKey = PaceKey(encryptionKey, macKey)

        val mac = deriveMac(paceKey.mac, piccPublicKey, paceInfo.protocolId)
        val derivedMac =
            deriveMac(paceKey.mac, epGsSharedSecret.toEcPublicKey(), paceInfo.protocolId)

        val piccMac =
            parseAsn1KeyObject(
                HealthCardCommand
                    .generalAuthenticate(false, mac, 5)
                    .transmitSuccessfully()
                    .apdu.data,
            )

        check(piccMac.contentEquals(derivedMac)) { "Mutual authentication failed." }

        return paceKey
    }

    // Main PACE negotiation flow
    val paceInfo = initializePace()
    val (epGsSharedSecret, epPrivateKey) = performKeyExchange(paceInfo)
    val paceKey = performMutualAuthentication(paceInfo, epGsSharedSecret, epPrivateKey)
    return TrustedChannelScopeImpl(this, paceKey)
}

private fun parseAsn1KeyObject(asn1: ByteArray): ByteArray =
    Asn1Decoder(asn1).read {
        advanceWithTag(28, Asn1Tag.APPLICATION or Asn1Tag.CONSTRUCTED) {
            readTag()
            readBytes(readLength())
        }
    }

// Helper to derive AES keys
@OptIn(ExperimentalCryptoApi::class)
private fun deriveAESKey(
    sharedSecret: ByteArray,
    mode: Mode,
): SecretKey {
    val keyBytes = getAES128Key(sharedSecret, mode)
    return SecretKey(keyBytes)
}

// Derive MAC from a key
@OptIn(ExperimentalCryptoApi::class)
private fun deriveMac(
    key: SecretKey,
    publicKey: EcPublicKey,
    protocolID: String,
): ByteArray {
    val authToken = createAsn1AuthToken(publicKey, protocolID)
    return useCrypto {
        CmacSpec(CmacAlgorithm.Aes).createCmac(key).let {
            it.update(authToken)
            it.final().copyOfRange(0, 8)
        }
    }
}

// Create ASN.1 Authentication Token
@OptIn(ExperimentalCryptoApi::class)
internal fun createAsn1AuthToken(
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
