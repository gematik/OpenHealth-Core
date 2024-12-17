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

@file:Suppress("ImplicitDefaultLocale")

package de.gematik.openhealth.smartcard.identifier

private const val AID_MIN_LENGTH = 5
private const val AID_MAX_LENGTH = 16

/**
 * An application identifier (AID) is used to address an application on the card
 */
class ApplicationIdentifier(
    aid: ByteArray,
) {
    val aid: ByteArray = aid.copyOf()
        get() =
            field.copyOf()

    init {
        require(!(aid.size < AID_MIN_LENGTH || aid.size > AID_MAX_LENGTH)) {
            // gemSpec_COS#N010.200
            "Application File Identifier length out of valid range [$AID_MIN_LENGTH,$AID_MAX_LENGTH]"
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    constructor(hexAid: String) : this(hexAid.hexToByteArray())
}