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

package de.gematik.ti.healthcard.model.card

/**
 * Represent the Version2 information of HealthCard
 */
class HealthCardVersion2(
    /**
     * Information of C0 with version of filling instruction for version2
     */
    val fillingInstructionsVersion: ByteArray, // C0
    /**
     * Information of C1 with version of card object system
     */
    val objectSystemVersion: ByteArray, // C1
    /**
     * Information of C2 with version of product identification object system
     */
    val productIdentificationObjectSystemVersion: ByteArray, // C2
    /**
     * Information of C4 with version of filling instruction for EF.GDO
     */
    val fillingInstructionsEfGdoVersion: ByteArray, // C4
    /**
     * Information of C5 with version of filling instruction for EF.ATR
     */
    val fillingInstructionsEfAtrVersion: ByteArray, // C5
    /**
     * Information of C6 with version of filling instruction for EF.KeyInfo
     * Only filled for gSMC-K and gSMC-KT
     */
    val fillingInstructionsEfKeyInfoVersion: ByteArray, // C6  //only  gSMC-K and gSMC-KT
    /**
     * Information of C3 with version of filling instruction for Environment Settings
     * Only filled for gSMC-K
     */
    val fillingInstructionsEfEnvironmentSettingsVersion: ByteArray, // C3  //only  gSMC-K
    /**
     * Information of C7 with version of filling instruction for EF.GDO
     */
    val fillingInstructionsEfLoggingVersion: ByteArray, // C7
) {
    companion object {
        private fun processData(data: ByteArray): Map<Int, ByteArray> =
            ASN1InputStream(data).use { decoder ->
                val tagMap = mutableMapOf<Int, ByteArray>()
                (decoder.readObject() as DLTaggedObject)
                    .let {
                        (it.baseObject as DLSequence).objects.iterator().forEach { obj ->
                            tagMap[(obj as DLTaggedObject).tagNo] =
                                (obj.baseObject as DEROctetString).octets
                        }
                    }
                tagMap
            }

        /**
         * Create and fill a new instance of Version2 Object with available data from card response data
         *
         * @param data
         * response data from card
         *
         * @return new instance of Version2
         *
         * @throws IOException
         */
        fun of(data: ByteArray) =
            processData(data).let {
                HealthCardVersion2(
                    fillingInstructionsVersion = it[0] ?: byteArrayOf(),
                    objectSystemVersion = it[1] ?: byteArrayOf(),
                    productIdentificationObjectSystemVersion = it[2] ?: byteArrayOf(),
                    fillingInstructionsEfEnvironmentSettingsVersion = it[3] ?: byteArrayOf(),
                    fillingInstructionsEfGdoVersion = it[4] ?: byteArrayOf(),
                    fillingInstructionsEfAtrVersion = it[5] ?: byteArrayOf(),
                    fillingInstructionsEfKeyInfoVersion = it[6] ?: byteArrayOf(),
                    fillingInstructionsEfLoggingVersion = it[7] ?: byteArrayOf(),
                )
            }
    }
}

const val EGK21_MIN_VERSION = (4 shl 16) or (4 shl 8) or 0

fun HealthCardVersion2.isEGK21(): Boolean {
    val v = this.objectSystemVersion
    val version = (v[0].toInt() shl 16) or (v[1].toInt() shl 8) or v[1].toInt()

    return version >= EGK21_MIN_VERSION
}