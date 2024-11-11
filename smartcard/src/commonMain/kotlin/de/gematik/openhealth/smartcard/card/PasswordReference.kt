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
 * A password can be a regular password or multireference password:
 * - A "regular password" is used to store a secret, which is usually only known to one cardholder.
 *   The COS will allow certain services only if this secret has been successfully presented as
 *   part of a user verification. The need for user verification can be turned on (enable) or
 *   turned off (disable).
 * - A multireference password allows the use of a secret, which is stored as an at-tributary in a
 *   regular password (see (gemSpec_COS_3.14.0#N015.200)), but under conditions that deviate from those of the
 *   regular password.
 */

private const val MIN_PWD_ID = 0
private const val MAX_PWD_ID = 31

/**
 * Represents a reference to a password on the card.
 *
 * @property pwdId The ID of the password.
 */
class PasswordReference(
    val pwdId: Int,
) : ICardKeyReference {
    init {
        require(!(pwdId < MIN_PWD_ID || pwdId > MAX_PWD_ID)) {
            // gemSpec_COS_3.14.0#N015.000
            "Password ID out of range [$MIN_PWD_ID,$MAX_PWD_ID]"
        }
    }

    // gemSpec_COS_3.14.0#N072.800
    override fun calculateKeyReference(dfSpecific: Boolean): Int =
        pwdId +
            if (dfSpecific) {
                ICardKeyReference.DF_SPECIFIC_PWD_MARKER
            } else {
                0
            }
}
