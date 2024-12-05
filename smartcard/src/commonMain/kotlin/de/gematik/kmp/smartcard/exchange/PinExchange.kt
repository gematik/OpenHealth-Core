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

package de.gematik.kmp.smartcard.exchange

import de.gematik.kmp.smartcard.card.EncryptedPinFormat2
import de.gematik.kmp.smartcard.card.ICardChannel
import de.gematik.kmp.smartcard.card.PasswordReference
import de.gematik.kmp.smartcard.cardobjects.Mf
import de.gematik.kmp.smartcard.command.HealthCardCommand
import de.gematik.kmp.smartcard.command.ResponseStatus
import de.gematik.kmp.smartcard.command.UnlockMethod
import de.gematik.kmp.smartcard.command.changeReferenceData
import de.gematik.kmp.smartcard.command.executeSuccessfulOn
import de.gematik.kmp.smartcard.command.select
import de.gematik.kmp.smartcard.command.unlockEgk
import de.gematik.kmp.smartcard.command.verifyPin

suspend fun ICardChannel.verifyPin(pin: String): ResponseStatus {
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .executeSuccessfulOn(this)

    val passwordReference = PasswordReference(Mf.MrPinHome.PWID)

    val response =
        HealthCardCommand
            .verifyPin(
                passwordReference = passwordReference,
                dfSpecific = false,
                pin = EncryptedPinFormat2(pin),
            ).executeOn(this)

    require(
        when (response.status) {
            ResponseStatus.SUCCESS,
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_01,
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_02,
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_03,
            ResponseStatus.PASSWORD_BLOCKED,
            ->
                true
            else ->
                false
        },
    ) { "Verify pin command failed with status: ${response.status}" }

    return response.status
}

suspend fun ICardChannel.unlockEgk(
    unlockMethod: String,
    puk: String,
    oldSecret: String,
    newSecret: String,
): ResponseStatus {
    HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .executeSuccessfulOn(this)

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
                ).executeSuccessfulOn(this)
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
                ).executeSuccessfulOn(this)
        }

    require(
        when (response.status) {
            ResponseStatus.SUCCESS ->
                true
            else ->
                false
        },
    ) { "Change secret command failed with status: ${response.status}" }

    return response.status
}