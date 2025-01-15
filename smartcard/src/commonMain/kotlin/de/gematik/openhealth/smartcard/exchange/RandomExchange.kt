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

package de.gematik.openhealth.smartcard.exchange

import de.gematik.openhealth.smartcard.Requirement
import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.ResponseStatus
import de.gematik.openhealth.smartcard.command.executeSuccessfulOn
import de.gematik.openhealth.smartcard.command.getRandomValues
import de.gematik.openhealth.smartcard.command.select

@Requirement(
    "GS-A_4367#5",
    "GS-A_4368#4",
    sourceSpecification = "gemSpec_Krypt",
    rationale =
        "Random numbers are generated using the RNG of the health card." +
            "This generator fulfills BSI-TR-03116#3.4 PTG.2 required by gemSpec_COS#14.9.5.1",
)
fun SmartCard.CommunicationScope.getRandom(length: Int): ByteArray {
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .executeSuccessfulOn(this)

    while (true) {
        val response =
            HealthCardCommand
                .getRandomValues(
                    length = length,
                ).executeOn(this)

        require(
            when (response.status) {
                ResponseStatus.SUCCESS,
                ResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
                ->
                    true
                else ->
                    false
            },
        ) { "Get Random command failed with status: ${response.status}" }

        return response.apdu.data
    }
}