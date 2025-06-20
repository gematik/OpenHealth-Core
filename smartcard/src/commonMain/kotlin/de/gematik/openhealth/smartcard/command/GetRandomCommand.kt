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

package de.gematik.openhealth.smartcard.command

private const val CLA = 0x80
private const val INS = 0x84
private const val NO_MEANING = 0x00

/**
 * Creates a [HealthCardCommand] to request random values from the card.
 * Use case gemSpec_COS_3.14.0#14.9.5.1
 *
 * @param length The number of random bytes to request.
 * @return A [HealthCardCommand] for requesting random values.
 */
fun HealthCardCommand.Companion.getRandomValues(length: Int) =
// REQ-BEGIN: GS-A_4367, GS-A_4368
// | gemSpec_Krypt
// | Random numbers are generated using the RNG of the health card.
// This generator fulfills BSI-TR-03116#3.4 PTG.2 required by gemSpec_COS_3.14.0#14.9.5.1
    HealthCardCommand(
        expectedStatus = getRandomValuesStatus,
        cla = CLA,
        ins = INS,
        p1 = NO_MEANING,
        p2 = NO_MEANING,
        ne = length,
    )
// REQ-END: GS-A_4367, GS-A_4368
