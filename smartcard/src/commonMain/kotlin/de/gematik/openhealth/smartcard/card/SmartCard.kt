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

package de.gematik.openhealth.smartcard.card

import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import kotlin.js.JsExport

/**
 * Represents a smart card interface, providing functionalities to interact with a smart card.
 */
@JsExport
abstract class SmartCard {
    /**
     * Defines the communication scope for interacting with a specific smart card.
     */
    interface CommunicationScope {
        /**
         * The identifier of the card, typically representing its name or unique label.
         */
        val cardIdentifier: String

        /**
         * Indicates whether the card supports extended length APDU commands.
         */
        val supportsExtendedLength: Boolean

        /**
         * Transmits a command APDU to the smart card and receives the corresponding response APDU.
         */
        @JsExport.Ignore
        suspend fun transmit(commandApdu: CardCommandApdu): CardResponseApdu

        /**
         * Ensures extensibility for specific APDU commands.
         */
        @JsExport.Ignore
        companion object
    }

    /**
     * Establishes a connection with the smart card and provides a communication scope for interaction.
     *
     * The connection is automatically managed, ensuring proper resource handling.
     *
     * @param block of code to execute within the communication scope.
     */
    @JsExport.Ignore
    abstract suspend fun <T> connect(block: suspend CommunicationScope.() -> T): T
}
