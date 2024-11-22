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

package de.gematik.kmp.healthcard

import de.gematik.kmp.healthcard.model.card.ICardChannel
import de.gematik.kmp.healthcard.model.card.IHealthCard
import de.gematik.kmp.healthcard.model.command.CommandApdu
import de.gematik.kmp.healthcard.model.command.HealthCardCommand
import de.gematik.kmp.healthcard.model.command.ResponseApdu

class TestChannel : ICardChannel {
    private var lastCommandAPDU: CommandApdu? = null

    val lastCommandAPDUBytes: ByteArray
        get() = lastCommandAPDU?.bytes ?: ByteArray(0)

    override val card: IHealthCard = object : IHealthCard {
        override fun transmit(apduCommand: CommandApdu): ResponseApdu {
            TODO("Not yet implemented")
        }
    }

    override val maxTransceiveLength: Int = 261

    override suspend fun transmit(command: CommandApdu): ResponseApdu {
        lastCommandAPDU = command
        return ResponseApdu(byteArrayOf(0x90.toByte(), 0x00))
    }

    override val isExtendedLengthSupported: Boolean = true

    suspend fun test(cmd: HealthCardCommand): ByteArray {
        cmd.executeOn(this@TestChannel)
        return lastCommandAPDUBytes
    }
}
