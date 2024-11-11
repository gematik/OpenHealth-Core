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

package de.gematik.openhealth.smartcard.identifier

private const val MIN_VALUE = 1
private const val MAX_VALUE = 30

/**
 * It is possible that the attribute type shortFileIdentifier is used by the file object types.
 * Short file identifiers are used  for implicit file selection in the immediate context of a command.
 * The value of shortFileIdentifier MUST be an integer in the interval [1, 30]
 *
 * ISO/IEC7816-4 and gemSpec_COS_3.14.0
 */
class ShortFileIdentifier(
    val sfId: Int,
) {
    init {
        sanityCheck()
    }

    @OptIn(ExperimentalStdlibApi::class)
    constructor(hexSfId: String) : this(hexSfId.hexToByteArray()[0].toInt())

    @Suppress("ImplicitDefaultLocale")
    private fun sanityCheck() {
        require(!(sfId < MIN_VALUE || sfId > MAX_VALUE)) {
            // gemSpec_COS_3.14.0#N007.000
            "Short File Identifier out of valid range [$MIN_VALUE,$MAX_VALUE]"
        }
    }
}
