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

import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlin.js.JsExport

/**
 * Defines the communication scope for interacting with a specific smart card.
 */
interface SmartCardCommunicationScope {
    /**
     * Indicates whether the card supports extended length APDU commands.
     */
    val supportsExtendedLength: Boolean

    /**
     * Transmits a command APDU to the smart card and receives the corresponding response APDU.
     */
    fun transmit(
        commandApdu: CardCommandApdu,
        response: (responseApdu: CardResponseApdu) -> Unit,
    )

    /**
     * Ensures extensibility for specific APDU commands.
     */
    @JsExport.Ignore
    companion object
}

/**
 * Transmits a command APDU to the smart card and receives the corresponding response APDU.
 */
suspend fun SmartCardCommunicationScope.transmit(commandApdu: CardCommandApdu): CardResponseApdu =
    suspendCoroutine { cont -> transmit(commandApdu) { cont.resume(it) } }
