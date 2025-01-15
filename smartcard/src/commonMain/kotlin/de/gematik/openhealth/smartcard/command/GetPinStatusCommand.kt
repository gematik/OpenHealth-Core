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

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.smartcard.card.PasswordReference

/**
 * Command representing Get Pin Status Command gemSpec_COS#14.6.4
 */

private const val CLA = 0x80
private const val INS = 0x20
private const val NO_MEANING = 0x00

/**
 * Creates a [HealthCardCommand] to get the pin status.
 * Use case gemSpec_COS#14.6.4.1
 *
 * @param password the arguments for the Get Pin Status command
 * @param dfSpecific whether or not the password object specifies a Global or DF-specific.
 * true = DF-Specific, false = global
 */
fun HealthCardCommand.Companion.getPinStatus(
    password: PasswordReference,
    dfSpecific: Boolean,
) = HealthCardCommand(
    expectedStatus = pinStatus,
    cla = CLA,
    ins = INS,
    p1 = NO_MEANING,
    p2 = password.calculateKeyReference(dfSpecific),
)