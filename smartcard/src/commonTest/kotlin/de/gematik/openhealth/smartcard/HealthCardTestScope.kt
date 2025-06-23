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

package de.gematik.openhealth.smartcard

import de.gematik.openhealth.smartcard.card.HealthCardScope
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import de.gematik.openhealth.smartcard.command.HealthCardCommand

class HealthCardTestScope(
    override val supportsExtendedLength: Boolean = true,
) : HealthCardScope {
    private var lastCardCommandAPDU: CardCommandApdu? = null

    val lastCommandAPDUBytes: ByteArray
        get() = lastCardCommandAPDU?.apdu ?: ByteArray(0)

    override fun transmit(
        commandApdu: CardCommandApdu,
        response: (CardResponseApdu) -> Unit,
    ) {
        lastCardCommandAPDU = commandApdu
        response(CardResponseApdu(byteArrayOf(0x90.toByte(), 0x00)))
    }

    suspend fun test(cmd: HealthCardCommand): ByteArray {
        cmd.transmit()
        return lastCommandAPDUBytes
    }
}
