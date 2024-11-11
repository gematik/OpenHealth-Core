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

import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference

private const val CLA = 0x00
private const val UNLOCK_EGK_INS = 0x2C
private const val MODE_VERIFICATION_DATA_NEW_SECRET = 0x00
private const val MODE_VERIFICATION_DATA = 0x01

/**
 * Unlock methods for the eGK (electronic health card).
 */
enum class UnlockMethod {
    ChangeReferenceData,
    ResetRetryCounterWithNewSecret,
    ResetRetryCounter,
    None,
}

/**
 * Creates a [HealthCardCommand] for the UNLOCK eGK command.
 * (gemSpec_COS_3.14.0#14.6.5.1, gemSpec_COS_3.14.0#14.6.5.2)
 *
 * @param unlockMethod The method used to unlock the eGK.
 * @param passwordReference The password reference for the unlock operation.
 * @param dfSpecific Indicates if the operation is DF-specific.
 * @param puk The PUK (Personal Unblocking Key) in encrypted format.
 * @param newSecret The new secret (PIN) in encrypted format, if applicable.
 */
fun HealthCardCommand.Companion.unlockEgk(
    unlockMethod: UnlockMethod,
    passwordReference: PasswordReference,
    dfSpecific: Boolean,
    puk: EncryptedPinFormat2,
    newSecret: EncryptedPinFormat2?,
) = HealthCardCommand(
    expectedStatus = unlockEgkStatus,
    cla = CLA,
    ins = UNLOCK_EGK_INS,
    p1 =
        if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret) {
            MODE_VERIFICATION_DATA_NEW_SECRET
        } else {
            MODE_VERIFICATION_DATA
        },
    p2 = passwordReference.calculateKeyReference(dfSpecific),
    data =
        if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret) {
            puk.bytes + (newSecret?.bytes ?: byteArrayOf())
        } else {
            puk.bytes
        },
)
