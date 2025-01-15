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

import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference

private const val CLA = 0x00
private const val INS = 0x24
private const val MODE_VERIFICATION_DATA = 0x00

/**
 * Creates a [HealthCardCommand] to change a secret.
 *
 * Use case change reference data  gemSpec_COS#14.6.1.1
 * @param passwordReference The [PasswordReference] to change.
 * @param dfSpecific `true` if the reference is DF-specific, `false` otherwise.
 * @param oldSecret The current secret.
 * @param newSecret The new secret.
 * @return A [HealthCardCommand] for changing the reference data.
 * @see PasswordReference
 * @see EncryptedPinFormat2
 *
 */
fun HealthCardCommand.Companion.changeReferenceData(
    passwordReference: PasswordReference,
    dfSpecific: Boolean,
    oldSecret: EncryptedPinFormat2,
    newSecret: EncryptedPinFormat2,
) = HealthCardCommand(
    expectedStatus = changeReferenceDataStatus,
    cla = CLA,
    ins = INS,
    p1 = MODE_VERIFICATION_DATA,
    p2 = passwordReference.calculateKeyReference(dfSpecific),
    data = oldSecret.bytes + newSecret.bytes,
)