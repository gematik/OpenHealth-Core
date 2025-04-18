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

package de.gematik.openhealth.smartcard.card

/**
 * interface that identifier:
 *
 * - symmetric authentication object,
 * - symmetric map connection object,
 * - or private key object
 */
interface ICardKeyReference {
    /**
     * Calculate the key reference for the given object.
     */
    fun calculateKeyReference(dfSpecific: Boolean): Int

    /**
     * DF Specific Password Marker
     */
    companion object {
        const val DF_SPECIFIC_PWD_MARKER = 0x80
    }
}
