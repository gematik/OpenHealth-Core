/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.exchange

import de.gematik.ti.healthcard.model.card.EncryptedPinFormat2
import de.gematik.ti.healthcard.model.card.ICardChannel
import de.gematik.ti.healthcard.model.command.ResponseStatus
import de.gematik.ti.healthcard.model.command.changeReferenceData
import de.gematik.ti.healthcard.model.command.executeSuccessfulOn
import de.gematik.ti.healthcard.model.command.select
import de.gematik.ti.healthcard.model.command.unlockEgk
import de.gematik.ti.healthcard.model.command.verifyPin
import de.gematik.ti.healthcard.model.nfc.card.PasswordReference

fun ICardChannel.verifyPin(pin: String): ResponseStatus {
    de.gematik.ti.healthcard.model.command.HealthCardCommand.select(selectParentElseRoot = false, readFirst = false)
        .executeSuccessfulOn(this)

    val passwordReference = PasswordReference(de.gematik.ti.healthcard.model.cardobjects.Mf.MrPinHome.PWID)

    val response =
        de.gematik.ti.healthcard.model.command.HealthCardCommand.verifyPin(
            passwordReference = passwordReference,
            dfSpecific = false,
            pin = EncryptedPinFormat2(pin)
        ).executeOn(this)

    require(
        when (response.status) {
            ResponseStatus.SUCCESS,
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_01,
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_02,
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_03,
            ResponseStatus.PASSWORD_BLOCKED ->
                true
            else ->
                false
        }
    ) { "Verify pin command failed with status: ${response.status}" }

    return response.status
}

fun ICardChannel.unlockEgk(
    unlockMethod: String,
    puk: String,
    oldSecret: String,
    newSecret: String
): ResponseStatus {
    de.gematik.ti.healthcard.model.command.HealthCardCommand.select(selectParentElseRoot = false, readFirst = false)
        .executeSuccessfulOn(this)

    val passwordReference = PasswordReference(de.gematik.ti.healthcard.model.cardobjects.Mf.MrPinHome.PWID)

    val response = if (unlockMethod == de.gematik.ti.healthcard.model.command.UnlockMethod.ChangeReferenceData.name) {
        de.gematik.ti.healthcard.model.command.HealthCardCommand.changeReferenceData(
            passwordReference = passwordReference,
            dfSpecific = false,
            oldSecret = EncryptedPinFormat2(oldSecret),
            newSecret = EncryptedPinFormat2(newSecret)
        ).executeSuccessfulOn(this)
    } else {
        de.gematik.ti.healthcard.model.command.HealthCardCommand.unlockEgk(
            unlockMethod = unlockMethod,
            passwordReference = passwordReference,
            dfSpecific = false,
            puk = EncryptedPinFormat2(puk),
            newSecret = if (unlockMethod == de.gematik.ti.healthcard.model.command.UnlockMethod.ResetRetryCounterWithNewSecret.name) {
                EncryptedPinFormat2(newSecret)
            } else { null }
        ).executeSuccessfulOn(this)
    }

    require(
        when (response.status) {
            ResponseStatus.SUCCESS ->
                true
            else ->
                false
        }
    ) { "Change secret command failed with status: ${response.status}" }

    return response.status
}
