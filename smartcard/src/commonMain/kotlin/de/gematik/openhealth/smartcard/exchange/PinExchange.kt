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
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.command.unlockEgk
import de.gematik.openhealth.smartcard.command.verifyPin

sealed class HealthCardVerifyPinResult(val response: HealthCardResponse) {
    class Success(response: HealthCardResponse) : HealthCardVerifyPinResult(response)
    class WrongSecretWarning(response: HealthCardResponse, val retriesLeft: Int) : HealthCardVerifyPinResult(response)
    class CardBlocked(response: HealthCardResponse) : HealthCardVerifyPinResult(response)
}

suspend fun TrustedChannelScope.verifyPin(pin: String): HealthCardVerifyPinResult {
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .transmitSuccessfully()

    val passwordReference = PasswordReference(Mf.MrPinHome.PWID)

    val response =
        HealthCardCommand
            .verifyPin(
                passwordReference = passwordReference,
                dfSpecific = false,
                pin = EncryptedPinFormat2(pin),
            ).transmit()

   return when (response.status) {
        HealthCardResponseStatus.SUCCESS ->  HealthCardVerifyPinResult.Success(response)
        HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_01 ->  HealthCardVerifyPinResult.WrongSecretWarning(response, 1)
        HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_02 ->  HealthCardVerifyPinResult.WrongSecretWarning(response, 2)
        HealthCardResponseStatus.WRONG_SECRET_WARNING_COUNT_03 ->  HealthCardVerifyPinResult.WrongSecretWarning(response, 3)
        HealthCardResponseStatus.PASSWORD_BLOCKED ->  HealthCardVerifyPinResult.CardBlocked(response)
        else -> error("Verify pin command failed with status: ${response.status}")
    }
}

suspend fun TrustedChannelScope.unlockEgk(
    unlockMethod: String,
    puk: String,
    oldSecret: String,
    newSecret: String,
): HealthCardResponseStatus {
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .transmitSuccessfully()

    val passwordReference = PasswordReference(Mf.MrPinHome.PWID)

    val response =
        if (unlockMethod ==
            UnlockMethod.ChangeReferenceData.name
        ) {
            HealthCardCommand
                .changeReferenceData(
                    passwordReference = passwordReference,
                    dfSpecific = false,
                    oldSecret = EncryptedPinFormat2(oldSecret),
                    newSecret = EncryptedPinFormat2(newSecret),
                ).transmitSuccessfully()
        } else {
            HealthCardCommand
                .unlockEgk(
                    unlockMethod = unlockMethod,
                    passwordReference = passwordReference,
                    dfSpecific = false,
                    puk = EncryptedPinFormat2(puk),
                    newSecret =
                        if (unlockMethod ==
                            UnlockMethod.ResetRetryCounterWithNewSecret.name
                        ) {
                            EncryptedPinFormat2(newSecret)
                        } else {
                            null
                        },
                ).transmitSuccessfully()
        }

    require(
        when (response.status) {
            HealthCardResponseStatus.SUCCESS ->
                true
            else ->
                false
        },
    ) { "Change secret command failed with status: ${response.status}" }

    return response.status
}