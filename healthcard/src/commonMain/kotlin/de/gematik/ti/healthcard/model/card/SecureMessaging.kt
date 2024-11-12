@file:Suppress("MagicNumber")

/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.card

import de.gematik.ti.healthcard.model.command.CommandApdu
import de.gematik.ti.healthcard.model.command.EXPECTED_LENGTH_WILDCARD_EXTENDED
import de.gematik.ti.healthcard.model.command.EXPECTED_LENGTH_WILDCARD_SHORT
import de.gematik.ti.healthcard.model.command.ResponseApdu
import de.gematik.ti.healthcard.model.tagobjects.DataObject
import de.gematik.ti.healthcard.model.tagobjects.LengthObject
import de.gematik.ti.healthcard.model.tagobjects.MacObject
import de.gematik.ti.healthcard.model.tagobjects.StatusObject
import de.gematik.ti.healthcard.utils.Bytes.padData
import de.gematik.ti.healthcard.utils.Bytes.unPadData
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

class SecureMessaging(private val paceKey: PaceKey) {
    private val secureMessagingSSC: ByteArray = ByteArray(BLOCK_SIZE)

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
     *
     * @param commandApdu plain Command APDU
     * @return encrypted Command APDU
     */
    fun encrypt(commandApdu: CommandApdu): CommandApdu {
        val apduToEncrypt = commandApdu.bytes // copy

        incrementSSC()

        require(apduToEncrypt.size >= HEADER_SIZE) { "APDU must be at least 4 bytes long" }

        val header = apduToEncrypt.copyOfRange(0, HEADER_SIZE)
        setSecureMessagingCommand(header)

        val commandDataOutput = ByteArrayOutputStream()

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
                DataObject(data).taggedObject.encodeTo(commandDataOutput)
            }

        val le = commandApdu.rawNe?.also {
            // write length object to output
            LengthObject(it).taggedObject.encodeTo(commandDataOutput)
        } ?: -1

        val commandMacObject = MacObject(header, commandDataOutput, paceKey.mac, secureMessagingSSC)
        return createEncryptedCommand(
            le = le,
            data = commandDataOutput,
            do8E = commandMacObject.taggedObject,
            header = header
        )
    }

    private fun setSecureMessagingCommand(header: ByteArray) {
        require(header[0] != (header[0] or SECURE_MESSAGING_COMMAND)) { MALFORMED_SECURE_MESSAGING_APDU }
        header[0] = (header[0] or SECURE_MESSAGING_COMMAND)
    }

    private fun encryptData(paddedData: ByteArray) =
        getCipher(ENCRYPT_MODE).doFinal(paddedData)

    private fun createEncryptedCommand(
        le: Int,
        data: ByteArrayOutputStream,
        do8E: DERTaggedObject,
        header: ByteArray
    ): CommandApdu {
        val tempData = data
        // write do8E to output
        do8E.encodeTo(data)

        val ne = if (tempData.size() < 1 && le == -1) {
            EXPECTED_LENGTH_WILDCARD_SHORT
        } else if (tempData.size() < 1 && le > -1) {
            EXPECTED_LENGTH_WILDCARD_EXTENDED
        } else if (tempData.size() > 0 && le < 0) {
            if (data.size() <= 255) {
                EXPECTED_LENGTH_WILDCARD_SHORT
            } else {
                EXPECTED_LENGTH_WILDCARD_EXTENDED
            }
        } else EXPECTED_LENGTH_WILDCARD_EXTENDED

        return CommandApdu.ofOptions(
            cla = header[0].toInt() and 0xFF,
            cla = header[0].toInt() and 0xFF,
            ins = header[1].toInt() and 0xFF,
            p1 = header[2].toInt() and 0xFF,
            p2 = header[3].toInt() and 0xFF,
            data = data.toByteArray(),
            ne = ne
        )
    }

    /**
     * Decrypts an encrypted Response APDU
     */
    fun decrypt(responseApdu: ResponseApdu): ResponseApdu {
        val apduResponseBytes = responseApdu.bytes // copy
        val statusBytes = ByteArray(2)
        val macBytes = ByteArray(MAC_SIZE)

        var responseDataOutput = byteArrayOf()

        require(apduResponseBytes.size >= MIN_RESPONSE_SIZE) { MALFORMED_SECURE_MESSAGING_APDU }

        incrementSSC()

        val dataObject = getResponseObjects(statusBytes, macBytes, apduResponseBytes)
        // write data object to output
        dataObject?.taggedObject?.encodeTo(responseDataOutput)

        // write status object to output
        StatusObject(statusBytes).taggedObject.encodeTo(responseDataOutput)

        val responseMacObject = MacObject(
            commandOutput = responseDataOutput,
            kMac = paceKey.mac,
            ssc = secureMessagingSSC
        )
        checkMac(responseMacObject.mac, macBytes)

        return createDecryptedResponse(statusBytes, dataObject)
    }

    private fun checkMac(mac: ByteArray, macObject: ByteArray) {
        require(mac.contentEquals(macObject)) { "Secure Messaging MAC verification failed" }
    }

    private fun getResponseObjects(
        statusBytes: ByteArray,
        macBytes: ByteArray,
        apduResponseBytes: ByteArray
    ): DataObject? {
        val inputStream = ByteArrayInputStream(apduResponseBytes)

        var dataTag = 0x0.toByte()
        var data: ByteArray? = null

        var tag = inputStream.read().toByte()
        if (tag == DO_81_TAG.toByte() || tag == DO_87_TAG.toByte()) {
            dataTag = tag

            var size = inputStream.read()
            if (size > LENGTH_TAG) {
                val sizeBytes = ByteArray(size and BYTE_MASK)

                inputStream.readAndCheckExpectedLength(sizeBytes, sizeBytes.size)

                size = BigInteger(1, sizeBytes).toInt()
            }

            data = ByteArray(size)
            inputStream.readAndCheckExpectedLength(data, data.size)

            tag = inputStream.read().toByte()
        }

        require(tag == DO_99_TAG.toByte()) { MALFORMED_SECURE_MESSAGING_APDU }

        if (inputStream.read() == STATUS_SIZE) {
            inputStream.readAndCheckExpectedLength(statusBytes, STATUS_SIZE)

            tag = inputStream.read().toByte()
        }

        require(tag == DO_8E_TAG.toByte()) { MALFORMED_SECURE_MESSAGING_APDU }

        if (inputStream.read() == MAC_SIZE) {
            inputStream.readAndCheckExpectedLength(macBytes, MAC_SIZE)
        }

        require(inputStream.available() == 2) { MALFORMED_SECURE_MESSAGING_APDU }

        return data?.let {
            DataObject(it, dataTag)
        }
    }

    private fun createDecryptedResponse(
        statusBytes: ByteArray,
        dataObject: DataObject?
    ): ResponseApdu {
        val outputStream = ByteArrayOutputStream()
        if (dataObject != null) {
            if (dataObject.tag == DO_87_TAG.toByte()) {
                val dataDecrypted = removePaddingIndicator(dataObject.data).let {
                    getCipher(DECRYPT_MODE).doFinal(it)
                }
                outputStream.write(unPadData(dataDecrypted))
            } else {
                outputStream.write(dataObject.data)
            }
        }
        outputStream.write(statusBytes)
        return ResponseApdu(outputStream.toByteArray())
    }

    private fun removePaddingIndicator(dataBytes: ByteArray): ByteArray =
        dataBytes.copyOfRange(1, dataBytes.size)

    private fun getCipher(mode: Int): Cipher =
        Cipher.getInstance("AES/CBC/NoPadding", BCProvider).apply {
            val key: Key = SecretKeySpec(paceKey.enc, "AES")
            val iv = createCipherIV()
            val aps: AlgorithmParameterSpec = IvParameterSpec(iv)

            init(mode, key, aps)
        }

    private fun createCipherIV(): ByteArray =
        // ECB instead of CBC on purpose. COS doesn't support CBC for this.
        Cipher.getInstance("AES/ECB/NoPadding", BCProvider).let {
            val key: Key = SecretKeySpec(paceKey.enc, "AES")
            it.init(ENCRYPT_MODE, key)
            it.doFinal(secureMessagingSSC)
        }
}

private fun InputStream.readAndCheckExpectedLength(b: ByteArray, expected: Int) {
    val l = this.read(b, 0, expected)
    require(l == expected) { MALFORMED_SECURE_MESSAGING_APDU }
}
