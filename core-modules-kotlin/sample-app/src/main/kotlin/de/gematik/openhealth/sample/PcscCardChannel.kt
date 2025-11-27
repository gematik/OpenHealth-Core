// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package de.gematik.openhealth.sample

import de.gematik.openhealth.healthcard.CardChannel
import de.gematik.openhealth.healthcard.CardChannelException
import de.gematik.openhealth.healthcard.TrustedChannelException
import javax.smartcardio.CardChannel as PcscChannel
import javax.smartcardio.CardException
import javax.smartcardio.CommandAPDU

/**
 * Adapts the javax.smartcardio channel so it can be consumed by the UniFFI generated API.
 */
class PcscCardChannel(
    private val delegate: PcscChannel,
) : CardChannel {

    override fun supportsExtendedLength(): Boolean {
        val historicalBytes = delegate.card.atr.historicalBytes
        return historicalBytes != null && historicalBytes.size > 15
    }

    override fun transmit(command: ByteArray): ByteArray {
        try {
            val response = delegate.transmit(CommandAPDU(command))
            return response.bytes
        } catch (ex: CardException) {
            throw CardChannelException.Transport(
                TrustedChannelException.Transport(
                    code = 0u,
                    reason = ex.message ?: "PC/SC transmit failed",
                )
            )
        }
    }
}
