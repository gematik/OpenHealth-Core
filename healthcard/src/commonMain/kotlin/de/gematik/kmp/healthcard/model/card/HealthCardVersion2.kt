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

package de.gematik.kmp.healthcard.model.card

import de.gematik.kmp.asn1.Asn1Decoder
import de.gematik.kmp.asn1.Asn1Tag

const val EGK21_MIN_VERSION = (4 shl 16) or (4 shl 8) or 0

/**
 * Represents the Version 2 information of a HealthCard.
 */
class HealthCardVersion2(
    /**
     * Version information of C0: Filling instructions for Version 2.
     */
    val fillingInstructionsVersion: ByteArray, // C0
    /**
     * Version information of C1: Card object system.
     */
    val objectSystemVersion: ByteArray, // C1
    /**
     * Version information of C2: Product identification object system.
     */
    val productIdentificationObjectSystemVersion: ByteArray, // C2
    /**
     * Version information of C4: Filling instructions for EF.GDO.
     */
    val fillingInstructionsEfGdoVersion: ByteArray, // C4
    /**
     * Version information of C5: Filling instructions for EF.ATR.
     */
    val fillingInstructionsEfAtrVersion: ByteArray, // C5
    /**
     * Version information of C6: Filling instructions for EF.KeyInfo.
     * Applicable only for gSMC-K and gSMC-KT.
     */
    val fillingInstructionsEfKeyInfoVersion: ByteArray, // C6
    /**
     * Version information of C3: Filling instructions for Environment Settings.
     * Applicable only for gSMC-K.
     */
    val fillingInstructionsEfEnvironmentSettingsVersion: ByteArray, // C3
    /**
     * Version information of C7: Filling instructions for EF.Logging.
     */
    val fillingInstructionsEfLoggingVersion: ByteArray, // C7
)

fun HealthCardVersion2.isEGK21(): Boolean {
    val v = this.objectSystemVersion
    val version = (v[0].toInt() shl 16) or (v[1].toInt() shl 8) or v[1].toInt()

    return version >= EGK21_MIN_VERSION
}

fun parseHealthCardVersion2(asn1: ByteArray): HealthCardVersion2 =
    Asn1Decoder(asn1).read {
        advanceWithTag(0x0F, Asn1Tag.APPLICATION or Asn1Tag.CONSTRUCTED) {
            val parsedData = mutableMapOf<Int, ByteArray>()

            while (remainingLength > 0) {
                // TODO XXX-000: More descriptive api fro private tag handling
                val tag = readTag().tagNumber
                val length = readLength()
                val value = readBytes(length)
                parsedData[tag] = value
            }

            HealthCardVersion2(
                fillingInstructionsVersion = parsedData[0] ?: byteArrayOf(),
                objectSystemVersion = parsedData[1] ?: byteArrayOf(),
                productIdentificationObjectSystemVersion = parsedData[2] ?: byteArrayOf(),
                fillingInstructionsEfEnvironmentSettingsVersion = parsedData[3] ?: byteArrayOf(),
                fillingInstructionsEfGdoVersion = parsedData[4] ?: byteArrayOf(),
                fillingInstructionsEfAtrVersion = parsedData[5] ?: byteArrayOf(),
                fillingInstructionsEfKeyInfoVersion = parsedData[6] ?: byteArrayOf(),
                fillingInstructionsEfLoggingVersion = parsedData[7] ?: byteArrayOf(),
            )
        }
    }