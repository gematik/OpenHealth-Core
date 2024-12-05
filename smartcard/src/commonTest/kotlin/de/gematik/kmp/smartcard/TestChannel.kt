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

package de.gematik.kmp.smartcard

import de.gematik.kmp.smartcard.card.ICardChannel
import de.gematik.kmp.smartcard.card.IHealthCard
import de.gematik.kmp.smartcard.command.CardCommandApdu
import de.gematik.kmp.smartcard.command.CardResponseApdu
import de.gematik.kmp.smartcard.command.HealthCardCommand

class TestChannel : ICardChannel {
    private var lastCardCommandAPDU: CardCommandApdu? = null

    val lastCommandAPDUBytes: ByteArray
        get() = lastCardCommandAPDU?.bytes ?: ByteArray(0)

    override val card: IHealthCard =
        object : IHealthCard {
            override fun transmit(apduCommand: CardCommandApdu): CardResponseApdu {
                TODO("Not yet implemented")
            }
        }

    override val maxTransceiveLength: Int = 261

    override suspend fun transmit(command: CardCommandApdu): CardResponseApdu {
        lastCardCommandAPDU = command
        return CardResponseApdu(byteArrayOf(0x90.toByte(), 0x00))
    }

    override val isExtendedLengthSupported: Boolean = true

    suspend fun test(cmd: HealthCardCommand): ByteArray {
        cmd.executeOn(this@TestChannel)
        return lastCommandAPDUBytes
    }
}