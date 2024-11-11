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

import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.asn1.writeTaggedObject
import de.gematik.openhealth.crypto.CmacAlgorithm
import de.gematik.openhealth.crypto.CmacSpec
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.useCrypto
import de.gematik.openhealth.smartcard.utils.padData

private const val MAC_SIZE = 8
private const val BLOCK_SIZE = 16

/**
 * Mac object with TAG 8E (cryptographic checksum)
 *
 *
 * @param header byte array with extracted header from plain CommandApdu
 * @param commandDataOutput ByteArrayOutputStream with extracted data
 * and expected length from plain CommandApdu
 * @param kMac byte array with Session key for message authentication
 * @param ssc byte array with send sequence counter
 */
@OptIn(ExperimentalCryptoApi::class)
class MacObject(
    private val header: ByteArray? = null,
    private val commandOutput: ByteArray,
    private val kMac: SecretKey,
    private val ssc: ByteArray,
) {
    private var _mac: ByteArray = ByteArray(BLOCK_SIZE)
    val mac: ByteArray
        get() = _mac.copyOf()

    val encoded: ByteArray
        get() =
            Asn1Encoder().write {
                writeTaggedObject(0x0E, Asn1Tag.CONTEXT_SPECIFIC) {
                    write(_mac)
                }
            }

    init {
        calculateMac()
    }

    private fun calculateMac() {
        useCrypto {
            val cbcMac = CmacSpec(CmacAlgorithm.Aes).createCmac(kMac)
            cbcMac.update(ssc)

            if (header != null) {
                val paddedHeader = padData(header, BLOCK_SIZE)
                cbcMac.update(paddedHeader)
            }
            if (commandOutput.isNotEmpty()) {
                val paddedData = padData(commandOutput, BLOCK_SIZE)
                cbcMac.update(paddedData)
            }
            _mac = cbcMac.final().copyOfRange(0, MAC_SIZE)
        }
    }
}
