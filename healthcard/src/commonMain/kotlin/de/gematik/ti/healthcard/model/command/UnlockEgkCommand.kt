/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.model.card.EncryptedPinFormat2
import de.gematik.ti.healthcard.model.card.PasswordReference

private const val CLA = 0x00
private const val UNLOCK_EGK_INS = 0x2C
private const val MODE_VERIFICATION_DATA_NEW_SECRET = 0x00
private const val MODE_VERIFICATION_DATA = 0x01

enum class UnlockMethod {
    ChangeReferenceData,
    ResetRetryCounterWithNewSecret,
    ResetRetryCounter,
    None
}

/**
 * Use case unlock eGK with/without Secret (Pin) gemSpec_COS#14.6.5.1 und gemSpec_COS#14.6.5.2
 */
fun HealthCardCommand.Companion.unlockEgk(
    unlockMethod: String,
    passwordReference: PasswordReference,
    dfSpecific: Boolean,
    puk: EncryptedPinFormat2,
    newSecret: EncryptedPinFormat2?
) =
    HealthCardCommand(
        expectedStatus = unlockEgkStatus,
        cla = CLA,
        ins = UNLOCK_EGK_INS,
        p1 = if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret.name) {
            MODE_VERIFICATION_DATA_NEW_SECRET
        } else {
            MODE_VERIFICATION_DATA
        },
        p2 = passwordReference.calculateKeyReference(dfSpecific),
        data = if (unlockMethod == UnlockMethod.ResetRetryCounterWithNewSecret.name) {
            puk.bytes + (newSecret?.bytes ?: byteArrayOf())
        } else {
            puk.bytes
        }
    )
