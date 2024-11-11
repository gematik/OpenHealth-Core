/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.model.card.EncryptedPinFormat2
import de.gematik.ti.healthcard.model.nfc.card.PasswordReference

private const val CLA = 0x00
private const val VERIFY_SECRET_INS = 0x20
private const val MODE_VERIFICATION_DATA = 0x00

/**
 * Command representing Verify Secret Command gemSpec_COS#14.6.6
 */
fun HealthCardCommand.Companion.verifyPin(
    passwordReference: PasswordReference,
    dfSpecific: Boolean,
    pin: EncryptedPinFormat2
) =
    HealthCardCommand(
        expectedStatus = verifySecretStatus,
        cla = CLA,
        ins = VERIFY_SECRET_INS,
        p1 = MODE_VERIFICATION_DATA,
        p2 = passwordReference.calculateKeyReference(dfSpecific),
        data = pin.bytes
    )
