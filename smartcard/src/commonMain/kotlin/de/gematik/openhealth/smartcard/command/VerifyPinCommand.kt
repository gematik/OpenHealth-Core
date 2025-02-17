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
private const val VERIFY_SECRET_INS = 0x20
private const val MODE_VERIFICATION_DATA = 0x00

/**
 * Creates a [HealthCardCommand] for the VERIFY SECRET command.
 * (gemSpec_COS#14.6.6)
 *
 * @param passwordReference The password reference for the verification.
 * @param dfSpecific Indicates if the verification is DF-specific.
 * @param pin The PIN (Personal Identification Number) in encrypted format.
 */
fun HealthCardCommand.Companion.verifyPin(
    passwordReference: PasswordReference,
    dfSpecific: Boolean,
    pin: EncryptedPinFormat2,
) = HealthCardCommand(
    expectedStatus = verifySecretStatus,
    cla = CLA,
    ins = VERIFY_SECRET_INS,
    p1 = MODE_VERIFICATION_DATA,
    p2 = passwordReference.calculateKeyReference(dfSpecific),
    data = pin.bytes,
)
