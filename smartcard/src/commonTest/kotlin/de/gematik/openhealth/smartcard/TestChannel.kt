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

package de.gematik.openhealth.smartcard

import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import de.gematik.openhealth.smartcard.command.HealthCardCommand

class TestChannel(
    override val cardIdentifier: String = "",
    override val supportsExtendedLength: Boolean = true,
) : SmartCard.CommunicationScope {
    private var lastCardCommandAPDU: CardCommandApdu? = null

    val lastCommandAPDUBytes: ByteArray
        get() = lastCardCommandAPDU?.bytes ?: ByteArray(0)

    override fun transmit(command: CardCommandApdu): CardResponseApdu {
        lastCardCommandAPDU = command
        return CardResponseApdu(byteArrayOf(0x90.toByte(), 0x00))
    }

    fun test(cmd: HealthCardCommand): ByteArray {
        cmd.executeOn(this@TestChannel)
        return lastCommandAPDUBytes
    }
}