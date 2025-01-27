/*
 * Copyright (c) 2025 gematik GmbH
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

import de.gematik.openhealth.smartcard.card.EncryptedPinFormat2
import de.gematik.openhealth.smartcard.card.PasswordReference
import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.HealthCardResponse
import de.gematik.openhealth.smartcard.command.HealthCardResponseStatus
import de.gematik.openhealth.smartcard.command.UnlockMethod
import de.gematik.openhealth.smartcard.command.changeReferenceData
import de.gematik.openhealth.smartcard.command.getPinStatus
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.command.unlockEgk
import de.gematik.openhealth.smartcard.command.verifyPin

sealed class HealthCardVerifyPinResult(val response: HealthCardResponse) {
    class Success(response: HealthCardResponse) : HealthCardVerifyPinResult(response)
    class WrongSecretWarning(response: HealthCardResponse, val retriesLeft: Int) : HealthCardVerifyPinResult(response)
    class CardBlocked(response: HealthCardResponse) : HealthCardVerifyPinResult(response)
}

/**
 * Verifies the PIN of the eGK.
 *
 * Steps:
 * 1. Select the appropriate file (gemSpec_COS#14.2.3.1).
 * 2. Get the PIN status (gemSpec_COS#14.7.3.2).
 * 3. Perform PIN verification (gemSpec_COS#14.7.3.3).
 *
 * @param pin The PIN entered by the user.
 * @return A result object indicating success, wrong PIN with retry count, or a blocked card.
 */
suspend fun TrustedChannelScope.verifyPin(pin: String): HealthCardVerifyPinResult {
    // Step 1: Select the appropriate context (e.g., root or parent file).
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .transmitSuccessfully()

    val passwordReference = PasswordReference(Mf.MrPinHome.PWID)

    // Step 2: Check the current PIN status.
    val pinStatus = HealthCardCommand.getPinStatus(passwordReference, dfSpecific = false).transmit()

    // Step 3: Perform the VERIFY PIN command if the status is not successful.
    return if (pinStatus.status == HealthCardResponseStatus.SUCCESS) {
        HealthCardVerifyPinResult.Success(pinStatus)
    } else {
        val response = HealthCardCommand.verifyPin(
            passwordReference = passwordReference,
            dfSpecific = false,
            pin = EncryptedPinFormat2(pin) // Encrypt PIN using Format 2.
        ).transmit()
        response.toVerifyPinResult()
    }
}

/**
 * Maps the response of a VERIFY PIN command to the appropriate result object.
 */
private fun HealthCardResponse.toVerifyPinResult(): HealthCardVerifyPinResult {
    return when (this.status) {
        HealthCardResponseStatus.SUCCESS -> HealthCardVerifyPinResult.Success(this)
        HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_01 -> HealthCardVerifyPinResult.WrongSecretWarning(this, 1)
        HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_02 -> HealthCardVerifyPinResult.WrongSecretWarning(this, 2)
        HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_03 -> HealthCardVerifyPinResult.WrongSecretWarning(this, 3)
        HealthCardResponseStatus.PASSWORD_BLOCKED -> HealthCardVerifyPinResult.CardBlocked(this)
        else -> error("VERIFY PIN command failed with status: ${this.status}")
    }
}

/**
 * Unlocks the eGK using PUK or by changing the reference data.
 *
 * Steps:
 * 1. Select the appropriate file (gemSpec_COS#14.2.3.1).
 * 2. Perform the CHANGE REFERENCE DATA or UNBLOCK PIN command (gemSpec_COS#14.7.3.4).
 *
 * @param unlockMethod The method used to unlock the eGK.
 * @param puk The PUK code (required for certain unlock methods).
 * @param oldSecret The current PIN (for change reference data).
 * @param newSecret The new PIN (for reset or change reference data).
 * @return The status of the unlock operation.
 */
suspend fun TrustedChannelScope.unlockEgk(
    unlockMethod: String,
    puk: String,
    oldSecret: String,
    newSecret: String,
): HealthCardResponseStatus {
    // Step 1: Select the appropriate context.
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .transmitSuccessfully()

    val passwordReference = PasswordReference(Mf.MrPinHome.PWID)

    // Step 2: Execute the appropriate unlock method.
    val response =
        if (unlockMethod == UnlockMethod.ChangeReferenceData.name) {
            // Change the reference data (gemSpec_COS#14.7.3.4).
            HealthCardCommand
                .changeReferenceData(
                    passwordReference = passwordReference,
                    dfSpecific = false,
                    oldSecret = EncryptedPinFormat2(oldSecret),
                    newSecret = EncryptedPinFormat2(newSecret),
                ).transmitSuccessfully()
        } else {
            // Unblock PIN or reset retry counter (gemSpec_COS#14.7.3.5).
            HealthCardCommand
                .unlockEgk(
                    unlockMethod = unlockMethod,
                    passwordReference = passwordReference,
                    dfSpecific = false,
                    puk = EncryptedPinFormat2(puk),
                    newSecret =
                        if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret.name) {
                            EncryptedPinFormat2(newSecret)
                        } else {
                            null
                        },
                ).transmitSuccessfully()
        }

    // Validate the response status.
    require(response.status == HealthCardResponseStatus.SUCCESS) {
        "Unlock eGK command failed with status: ${response.status}"
    }

    return response.status
}