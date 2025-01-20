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

import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.bytes
import de.gematik.openhealth.crypto.cipher.AesCbcSpec
import de.gematik.openhealth.crypto.cipher.AesEcbSpec
import de.gematik.openhealth.crypto.useCrypto
import de.gematik.openhealth.smartcard.card.PaceKey
import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_EXTENDED
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_SHORT
import de.gematik.openhealth.smartcard.tagobjects.DataObject
import de.gematik.openhealth.smartcard.tagobjects.StatusObject
import de.gematik.openhealth.smartcard.tagobjects.LengthObject

import de.gematik.openhealth.smartcard.utils.Bytes.padData
import de.gematik.openhealth.smartcard.utils.Bytes.unPadData
import kotlin.experimental.or


private const val SECURE_MESSAGING_COMMAND = 0x0C.toByte()
private val PADDING_INDICATOR = byteArrayOf(0x01.toByte())
private const val BLOCK_SIZE = 16
private const val MAC_SIZE = 8
private const val STATUS_SIZE: Int = 0x02
private const val MIN_RESPONSE_SIZE = 12
private const val HEADER_SIZE = 4

private const val DO_81_TAG = 0x81
private const val DO_87_TAG = 0x87
private const val DO_99_TAG = 0x99
private const val DO_8E_TAG = 0x8E
private const val LENGTH_TAG = 0x80
private const val BYTE_MASK = 0x0F
private const val MALFORMED_SECURE_MESSAGING_APDU = "Malformed Secure Messaging APDU"

interface SecureMessagingScope : SmartCard.CommunicationScope {

}

@OptIn(ExperimentalCryptoApi::class)
class SecureMessaging(private val scope: SmartCard.CommunicationScope, private val paceKey: PaceKey): SecureMessagingScope {
    private val secureMessagingSSC: ByteArray = ByteArray(BLOCK_SIZE)

    override val cardIdentifier: String = scope.cardIdentifier
    override val supportsExtendedLength: Boolean = scope.supportsExtendedLength

    override fun transmit(apdu: CardCommandApdu): CardResponseApdu {
        TODO("Not yet implemented")
    }

    private fun incrementSSC() {
        for (i in secureMessagingSSC.indices.reversed()) {
            secureMessagingSSC[i]++
            if (secureMessagingSSC[i] != 0.toByte()) {
                break
            }
        }
    }

    /**
     * Encrypts a plain APDU
     */
    @OptIn(ExperimentalStdlibApi::class)
    fun encrypt(commandApdu: CardCommandApdu): CardCommandApdu {
        val apduToEncrypt = commandApdu.apdu // copy

        incrementSSC()

        require(apduToEncrypt.size >= HEADER_SIZE) { "APDU must be at least 4 bytes long" }

        val header = apduToEncrypt.copyOfRange(0, HEADER_SIZE)
        setSecureMessagingCommand(header)

        var commandDataOutput = byteArrayOf()

        apduToEncrypt.copyOfRange(
            commandApdu.dataOffset,
            commandApdu.dataOffset + commandApdu.rawNc
        )
            .takeIf { it.isNotEmpty() }
            ?.let {
                var data = it
                data = padData(data, BLOCK_SIZE)
                data = encryptData(data)
                data = PADDING_INDICATOR + data

                // write encrypted data to output
                commandDataOutput += DataObject.encrypted(data).encoded
            }


        val le = commandApdu.rawNe?.also {
            // write length object to output
            commandDataOutput += LengthObject(it).encoded
        } ?: -1

        val commandMacObject = MacObject(header, commandDataOutput, paceKey.mac, secureMessagingSSC)
        commandDataOutput += commandMacObject.encoded
        return createEncryptedCommand(
            le = le,
            data = commandDataOutput,
            header = header
        )
    }

    private fun setSecureMessagingCommand(header: ByteArray) {
        require(header[0] != (header[0] or SECURE_MESSAGING_COMMAND)) { MALFORMED_SECURE_MESSAGING_APDU }
        header[0] = (header[0] or SECURE_MESSAGING_COMMAND)
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

        require(apduResponseBytes.size >= MIN_RESPONSE_SIZE) { MALFORMED_SECURE_MESSAGING_APDU }

        incrementSSC()

        val responseObject = responseApdu.readResponseObject()
        // write data object to output
        responseObject.dataObject?.encoded?.let { responseDataOutput += it }

        // write status object to output
        responseDataOutput += StatusObject(responseObject.statusBytes).encoded

        val responseMacObject = MacObject(
            commandOutput = responseDataOutput,
            kMac = paceKey.mac,
            ssc = secureMessagingSSC
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
     * DO81...||DO99...||DO8E...||SW1SW2
     * DO87...||DO99...||DO8E...||SW1SW2
     */
    @OptIn(ExperimentalStdlibApi::class)
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
            require(statusBytes.size == 2) { "Status must be 2 bytes long" }
            // Case DO8E
            val macBytes = advanceWithTag(0x0E, Asn1Tag.CONTEXT_SPECIFIC) {
                readBytes(remainingLength)
            }
            require(macBytes.size == 8) { "Status must be 8 bytes long" }
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
                outputStream += unPadData(dataDecrypted)
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
            ecb.update(secureMessagingSSC) + ecb.final()
        }
}
