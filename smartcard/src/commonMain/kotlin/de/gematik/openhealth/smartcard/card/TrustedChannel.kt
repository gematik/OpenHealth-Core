/*
 * Copyright (c) 2025 gematik GmbH
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

package de.gematik.openhealth.smartcard.card

import MacObject
import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.bytes
import de.gematik.openhealth.crypto.cipher.AesCbcSpec
import de.gematik.openhealth.crypto.cipher.AesEcbSpec
import de.gematik.openhealth.crypto.useCrypto
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_EXTENDED
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_SHORT
import de.gematik.openhealth.smartcard.tagobjects.DataObject
import de.gematik.openhealth.smartcard.tagobjects.LengthObject
import de.gematik.openhealth.smartcard.tagobjects.StatusObject
import de.gematik.openhealth.smartcard.utils.padData
import de.gematik.openhealth.smartcard.utils.unpadData
import kotlin.collections.plus
import kotlin.experimental.or

private const val SECURE_MESSAGING_COMMAND = 0x0C.toByte()
private val PADDING_INDICATOR = byteArrayOf(0x01.toByte())
private const val CIPHER_BLOCK_SIZE_BYTES = 16
private const val APDU_RESPONSE_MAC_SIZE_BYTES = 8
private const val APDU_RESPONSE_STATUS_SIZE_BYTES = 2
private const val APDU_MIN_RESPONSE_SIZE_BYTES = 12
private const val APDU_HEADER_SIZE_BYTES = 4

@JsExport
interface TrustedChannelScope : HealthCardScope {
    val paceKey: PaceKey
}

@OptIn(ExperimentalCryptoApi::class)
internal class TrustedChannelScopeImpl(private val scope: HealthCardScope, override val paceKey: PaceKey): TrustedChannelScope, HealthCardScope {
    override val cardIdentifier: String = scope.cardIdentifier
    override val supportsExtendedLength: Boolean = scope.supportsExtendedLength

    private val secureMessagingSequenceCounter: ByteArray = ByteArray(CIPHER_BLOCK_SIZE_BYTES)

    override suspend fun transmit(commandApdu: CardCommandApdu): CardResponseApdu {
        val encryptedCommandApdu = encrypt(commandApdu)
        val encryptedResponseApdu = scope.transmit(encryptedCommandApdu)
        return decrypt(encryptedResponseApdu)
    }

    private fun incrementMsgSeqCounter() {
        for (i in secureMessagingSequenceCounter.indices.reversed()) {
            secureMessagingSequenceCounter[i]++
            if (secureMessagingSequenceCounter[i] != 0.toByte()) {
                break
            }
        }
    }

    fun encrypt(commandApdu: CardCommandApdu): CardCommandApdu {
        val apduToEncrypt = commandApdu.apdu

        incrementMsgSeqCounter()

        require(apduToEncrypt.size >= APDU_HEADER_SIZE_BYTES) { "APDU must be at least $APDU_HEADER_SIZE_BYTES bytes long" }

        val header = apduToEncrypt.copyOfRange(0, APDU_HEADER_SIZE_BYTES)
        require(header[0] != (header[0] or SECURE_MESSAGING_COMMAND)) { "Secure Messaging command already set" }
        // set secure messaging command on first header byte
        header[0] = header[0] or SECURE_MESSAGING_COMMAND

        var commandDataOutput = byteArrayOf()

        apduToEncrypt.copyOfRange(
            commandApdu.dataOffset,
            commandApdu.dataOffset + commandApdu.rawNc
        )
            .takeIf { it.isNotEmpty() }
            ?.let {
                var data = it
                data = padData(data, CIPHER_BLOCK_SIZE_BYTES)
                data = encryptData(data)
                data = PADDING_INDICATOR + data

                // write encrypted data to output
                commandDataOutput += DataObject.encrypted(data).encoded
            }


        val le = commandApdu.rawNe?.also {
            // write length object to output
            commandDataOutput += LengthObject(it).encoded
        } ?: -1

        val commandMacObject = MacObject(header, commandDataOutput, paceKey.mac, secureMessagingSequenceCounter)
        commandDataOutput += commandMacObject.encoded
        return createEncryptedCommand(
            le = le,
            data = commandDataOutput,
            header = header
        )
    }

    @OptIn(UnsafeCryptoApi::class, ExperimentalStdlibApi::class)
    private fun encryptData(paddedData: ByteArray) =
        useCrypto {
            val cbc = AesCbcSpec(
                tagLength = 16.bytes,
                iv = createIvWithEcb(),
                autoPadding = false,
            ).createCipher(paceKey.enc)
            cbc.update(paddedData) + cbc.final()
        }

    private fun createEncryptedCommand(
        le: Int,
        data: ByteArray,
        header: ByteArray
    ): CardCommandApdu {
        val tempData = data

        val ne = if (tempData.size < 1 && le == -1) {
            EXPECTED_LENGTH_WILDCARD_SHORT
        } else if (tempData.size < 1 && le > -1) {
            EXPECTED_LENGTH_WILDCARD_EXTENDED
        } else if (tempData.size > 0 && le < 0) {
            if (data.size <= 255) {
                EXPECTED_LENGTH_WILDCARD_SHORT
            } else {
                EXPECTED_LENGTH_WILDCARD_EXTENDED
            }
        } else EXPECTED_LENGTH_WILDCARD_EXTENDED

        return CardCommandApdu.ofOptions(
            cla = header[0].toInt() and 0xFF,
            ins = header[1].toInt() and 0xFF,
            p1 = header[2].toInt() and 0xFF,
            p2 = header[3].toInt() and 0xFF,
            data = data,
            ne = ne
        )
    }

    /**
     * Decrypts an encrypted Response APDU
     */
    fun decrypt(responseApdu: CardResponseApdu): CardResponseApdu {
        val apduResponseBytes = responseApdu.bytes // copy

        var responseDataOutput = byteArrayOf()

        require(apduResponseBytes.size >= APDU_MIN_RESPONSE_SIZE_BYTES) { "Apdu response is too short" }

        incrementMsgSeqCounter()

        val responseObject = responseApdu.readResponseObject()
        // write data object to output
        responseObject.dataObject?.encoded?.let { responseDataOutput += it }

        // write status object to output
        responseDataOutput += StatusObject(responseObject.statusBytes).encoded

        val responseMacObject = MacObject(
            commandOutput = responseDataOutput,
            kMac = paceKey.mac,
            ssc = secureMessagingSequenceCounter
        )
        checkMac(responseMacObject.mac, responseObject.macBytes)

        return createDecryptedResponse(responseObject.statusBytes, responseObject.dataObject)
    }

    private fun checkMac(mac: ByteArray, macObject: ByteArray) {
        require(mac.contentEquals(macObject)) { "Secure Messaging MAC verification failed" }
    }

    class ResponseObject(
        val dataObject: DataObject?,
        val statusBytes: ByteArray,
        val macBytes: ByteArray,
    )

    /**
     * Concatenated asn1 of the following structure:
     *
     * DO81...||DO99...||DO8E...||SW1SW2
     * DO87...||DO99...||DO8E...||SW1SW2
     *
     * while DO81 or DO87 can be optional.
     */
    private fun CardResponseApdu.readResponseObject(): ResponseObject =
        Asn1Decoder(this.data).read {
            val data = optional {
                advance(
                    {
                        // Case DO81
                        advanceWithTag(0x01, Asn1Tag.CONTEXT_SPECIFIC) {
                            Asn1Tag(
                                tagClass = Asn1Tag.CONTEXT_SPECIFIC,
                                tagNumber = 0x01
                            ) to readBytes(remainingLength)
                        }
                    },
                    {
                        // Case DO87
                        advanceWithTag(0x07, Asn1Tag.CONTEXT_SPECIFIC) {
                            Asn1Tag(
                                tagClass = Asn1Tag.CONTEXT_SPECIFIC,
                                tagNumber = 0x07
                            ) to readBytes(remainingLength)
                        }
                    }
                )
            }
            // Case DO99
            val statusBytes = advanceWithTag(0x19, Asn1Tag.CONTEXT_SPECIFIC) {
                readBytes(remainingLength)
            }
            require(statusBytes.size == APDU_RESPONSE_STATUS_SIZE_BYTES) { "Status must be $APDU_RESPONSE_STATUS_SIZE_BYTES bytes long" }
            // Case DO8E
            val macBytes = advanceWithTag(0x0E, Asn1Tag.CONTEXT_SPECIFIC) {
                readBytes(remainingLength)
            }
            require(macBytes.size == APDU_RESPONSE_MAC_SIZE_BYTES) { "Status must be $APDU_RESPONSE_MAC_SIZE_BYTES bytes long" }
            ResponseObject(
                dataObject = data?.let { (tag, data) -> DataObject(data, tag) },
                statusBytes = statusBytes,
                macBytes = macBytes,
            )
        }

    @OptIn(UnsafeCryptoApi::class)
    private fun createDecryptedResponse(
        statusBytes: ByteArray,
        dataObject: DataObject?
    ): CardResponseApdu {
        var outputStream = byteArrayOf()
        if (dataObject != null) {
            if (dataObject.isEncrypted) {
                val dataDecrypted = removePaddingIndicator(dataObject.data).let {
                    useCrypto {
                        val cbc = AesCbcSpec(
                            tagLength = 16.bytes,
                            iv = createIvWithEcb(),
                            autoPadding = false,
                        ).createDecipher(paceKey.enc)
                        cbc.update(it) + cbc.final()
                    }
                }
                outputStream += unpadData(dataDecrypted)
            } else {
                outputStream += dataObject.data
            }
        }
        outputStream += statusBytes
        return CardResponseApdu(outputStream)
    }

    private fun removePaddingIndicator(dataBytes: ByteArray): ByteArray =
        dataBytes.copyOfRange(1, dataBytes.size)

    @OptIn(UnsafeCryptoApi::class)
    private fun createIvWithEcb(): ByteArray =
        // ECB instead of CBC on purpose. COS doesn't support CBC for this.
        useCrypto {
            val ecb = AesEcbSpec(
                tagLength = 16.bytes,
                autoPadding = false,
            ).createCipher(paceKey.enc)
            ecb.update(secureMessagingSequenceCounter) + ecb.final()
        }
}
