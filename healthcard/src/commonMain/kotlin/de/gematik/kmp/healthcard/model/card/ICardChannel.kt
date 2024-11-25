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

package de.gematik.kmp.healthcard.model.card

import de.gematik.kmp.healthcard.model.command.CardCommandApdu
import de.gematik.kmp.healthcard.model.command.CardResponseApdu

/**
 * Interface to a (logical) channel of a smart card.
 * A channel object is used to send commands to and to receive answers from a smartcard.
 * This is done by sending so called A-PDUs [CardCommandApdu] to smartcard. A smartcard returns
 * a [CardResponseApdu]
 */
interface ICardChannel {
    /**
     * Returns the Card this channel is associated with.
     */
    val card: IHealthCard

    /**
     * Max transceive length
     */
    val maxTransceiveLength: Int

    /**
     * Transmits the specified [CardCommandApdu] to the associated smartcard and returns the
     * [CardResponseApdu].
     *
     * The CLA byte of the [CardCommandApdu] is automatically adjusted to match the channel number of this card channel
     * since the channel number is coded into CLA byte of a command APDU according to ISO 7816-4.
     *
     * Implementations should transparently handle artifacts of the transmission protocol.
     *
     * The ResponseAPDU returned by this method is the result after this processing has been performed.
     */
    suspend fun transmit(command: CardCommandApdu): CardResponseApdu

    /**
     * Identify whether a channel supports APDU extended length commands and
     * appropriate responses
     */
    val isExtendedLengthSupported: Boolean
}