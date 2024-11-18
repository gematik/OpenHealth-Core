

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.model.card.EncryptedPinFormat2
import de.gematik.ti.healthcard.model.card.PasswordReference

private const val CLA = 0x00
private const val INS = 0x24
private const val MODE_VERIFICATION_DATA = 0x00

/**
 * Use case change reference data  gemSpec_COS#14.6.1.1
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
    data =
        oldSecret.bytes + newSecret.bytes,
)