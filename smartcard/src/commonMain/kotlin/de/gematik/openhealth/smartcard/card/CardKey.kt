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

package de.gematik.openhealth.smartcard.card

private const val MIN_KEY_ID = 2
private const val MAX_KEY_ID = 28

/**
 * Class applies for symmetric keys and private keys.
 */
@Suppress("ImplicitDefaultLocale")
class CardKey(
    private val keyId: Int,
) : ICardKeyReference {
    init {
        require(!(keyId < MIN_KEY_ID || keyId > MAX_KEY_ID)) {
            // gemSpec_COS#N016.400 and #N017.100
            "Key ID out of range [$MIN_KEY_ID,$MAX_KEY_ID]"
        }
    }

    override fun calculateKeyReference(dfSpecific: Boolean): Int {
        // gemSpec_COS#N099.600
        var keyReference = keyId
        if (dfSpecific) {
            keyReference += ICardKeyReference.DF_SPECIFIC_PWD_MARKER
        }
        return keyReference
    }
}
