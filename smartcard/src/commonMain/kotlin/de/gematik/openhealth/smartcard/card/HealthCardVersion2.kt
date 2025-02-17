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

@file:Suppress("MagicNumber")

package de.gematik.openhealth.smartcard.card

import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.asn1.Asn1Tag

private const val HEALTH_CARD_21_MIN_VERSION = (4 shl 16) or (4 shl 8) or 0

/**
 * Represents the version 2 object of a german health card.
 */
class HealthCardVersion2(
    /**
     * Version information of C0: Filling instructions for Version 2.
     */
    val fillingInstructionsVersion: ByteArray,
    /**
     * Version information of C1: Card object system.
     */
    val objectSystemVersion: ByteArray,
    /**
     * Version information of C2: Product identification object system.
     */
    val productIdentificationObjectSystemVersion: ByteArray,
    /**
     * Version information of C4: Filling instructions for EF.GDO.
     */
    val fillingInstructionsEfGdoVersion: ByteArray,
    /**
     * Version information of C5: Filling instructions for EF.ATR.
     */
    val fillingInstructionsEfAtrVersion: ByteArray,
    /**
     * Version information of C6: Filling instructions for EF.KeyInfo.
     * Applicable only for gSMC-K and gSMC-KT.
     */
    val fillingInstructionsEfKeyInfoVersion: ByteArray,
    /**
     * Version information of C3: Filling instructions for Environment Settings.
     * Applicable only for gSMC-K.
     */
    val fillingInstructionsEfEnvironmentSettingsVersion: ByteArray,
    /**
     * Version information of C7: Filling instructions for EF.Logging.
     */
    val fillingInstructionsEfLoggingVersion: ByteArray,
)

/**
 * Returns `true` if the version of the health card is 2.1.
 */
fun HealthCardVersion2.isHealthCardVersion21(): Boolean {
    val v = this.objectSystemVersion
    val version = (v[0].toInt() shl 16) or (v[1].toInt() shl 8) or v[1].toInt()

    return version >= HEALTH_CARD_21_MIN_VERSION
}

/**
 * Parses the version 2 object of a german health card from its ASN1 representation.
 */
fun parseHealthCardVersion2(asn1: ByteArray): HealthCardVersion2 =
    Asn1Decoder(asn1).read {
        advanceWithTag(0x0F, Asn1Tag.PRIVATE or Asn1Tag.CONSTRUCTED) {
            val parsedData = mutableMapOf<Int, ByteArray>()

            while (remainingLength > 0) {
                // TODO OPEN-3: More descriptive api for private tag handling
                val tag = readTag().tagNumber
                val length = readLength()
                val value = readBytes(length)
                parsedData[tag] = value
            }

            HealthCardVersion2(
                fillingInstructionsVersion = parsedData.getOrEmpty(0),
                objectSystemVersion = parsedData.getOrEmpty(1),
                productIdentificationObjectSystemVersion = parsedData.getOrEmpty(2),
                fillingInstructionsEfEnvironmentSettingsVersion = parsedData.getOrEmpty(3),
                fillingInstructionsEfGdoVersion = parsedData.getOrEmpty(4),
                fillingInstructionsEfAtrVersion = parsedData.getOrEmpty(5),
                fillingInstructionsEfKeyInfoVersion = parsedData.getOrEmpty(6),
                fillingInstructionsEfLoggingVersion = parsedData.getOrEmpty(7),
            )
        }
    }

private fun MutableMap<Int, ByteArray>.getOrEmpty(nr: Int) = this[nr] ?: byteArrayOf()
