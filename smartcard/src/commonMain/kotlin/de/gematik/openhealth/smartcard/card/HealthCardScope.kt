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

import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.HealthCardResponse
import de.gematik.openhealth.smartcard.command.HealthCardResponseStatus
import de.gematik.openhealth.smartcard.command.ResponseException
import de.gematik.openhealth.smartcard.command.commandApdu
import de.gematik.openhealth.smartcard.command.requireSuccess
import kotlin.jvm.JvmSynthetic

/**
 * Scope for communicating with the health card.
 */
interface HealthCardScope : SmartCardCommunicationScope {
    /**
     * Transmits the command on the given [SmartCardCommunicationScope] and throws a [ResponseException]
     * if the command was not successful.
     */
    @JvmSynthetic
    suspend fun HealthCardCommand.transmitSuccessfully(): HealthCardResponse =
        transmit().also {
            it.requireSuccess()
        }

    /**
     * Transmits the command on the given [SmartCardCommunicationScope] and returns the response.
     */
    @JvmSynthetic
    suspend fun HealthCardCommand.transmit(): HealthCardResponse {
        val commandApdu = this.commandApdu(supportsExtendedLength)
        return transmit(commandApdu).let {
            HealthCardResponse(
                this.expectedStatus[it.sw] ?: HealthCardResponseStatus.UNKNOWN_STATUS,
                it,
            )
        }
    }
}

private class HealthCardScopeImpl(
    scope: SmartCardCommunicationScope,
) : HealthCardScope,
    SmartCardCommunicationScope by scope

/**
 * Creates a new [HealthCardScope] for the given [SmartCardCommunicationScope].
 *
 * @param scope The [SmartCardCommunicationScope] to use for communication.
 *
 */
fun SmartCardCommunicationScope.healthCardScope(): HealthCardScope = HealthCardScopeImpl(this)
