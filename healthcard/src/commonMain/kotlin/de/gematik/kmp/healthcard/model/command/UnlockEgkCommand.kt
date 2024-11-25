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

package de.gematik.kmp.healthcard.model.command

import de.gematik.kmp.healthcard.model.card.EncryptedPinFormat2
import de.gematik.kmp.healthcard.model.card.PasswordReference

private const val CLA = 0x00
private const val UNLOCK_EGK_INS = 0x2C
private const val MODE_VERIFICATION_DATA_NEW_SECRET = 0x00
private const val MODE_VERIFICATION_DATA = 0x01

enum class UnlockMethod {
    ChangeReferenceData,
    ResetRetryCounterWithNewSecret,
    ResetRetryCounter,
    None,
}

/**
 * Use case unlock eGK with/without Secret (Pin) gemSpec_COS#14.6.5.1 und gemSpec_COS#14.6.5.2
 */
fun HealthCardCommand.Companion.unlockEgk(
    unlockMethod: String,
    passwordReference: PasswordReference,
    dfSpecific: Boolean,
    puk: EncryptedPinFormat2,
    newSecret: EncryptedPinFormat2?,
) = HealthCardCommand(
    expectedStatus = unlockEgkStatus,
    cla = CLA,
    ins = UNLOCK_EGK_INS,
    p1 =
        if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret.name) {
            MODE_VERIFICATION_DATA_NEW_SECRET
        } else {
            MODE_VERIFICATION_DATA
        },
    p2 = passwordReference.calculateKeyReference(dfSpecific),
    data =
        if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret.name) {
            puk.bytes + (newSecret?.bytes ?: byteArrayOf())
        } else {
            puk.bytes
        },
)