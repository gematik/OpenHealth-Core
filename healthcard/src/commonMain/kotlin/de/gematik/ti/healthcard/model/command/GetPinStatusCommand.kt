

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.model.card.PasswordReference

/**
 * Command representing Get Pin Status Command gemSpec_COS#14.6.4
 */

private const val CLA = 0x80
private const val INS = 0x20
private const val NO_MEANING = 0x00

/**
 * Use case Get Pin Status gemSpec_COS#14.6.4.1
 *
 * @param password the arguments for the Get Pin Status command
 * @param dfSpecific whether or not the password object specifies a Global or DF-specific.
 * true = DF-Specific, false = global
 */
fun HealthCardCommand.Companion.getPinStatus(
    password: PasswordReference,
    dfSpecific: Boolean,
) = HealthCardCommand(
    expectedStatus = pinStatus,
    cla = CLA,
    ins = INS,
    p1 = NO_MEANING,
    p2 = password.calculateKeyReference(dfSpecific),
)