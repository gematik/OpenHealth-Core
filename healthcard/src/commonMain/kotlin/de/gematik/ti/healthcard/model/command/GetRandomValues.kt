

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.Requirement

/**
 * Commands representing Get Random command in gemSpec_COS#14.9.5
 */

private const val CLA = 0x80
private const val INS = 0x84
private const val NO_MEANING = 0x00

/**
 * Use case Get Random gemSpec_COS#14.9.5.1
 */
@Requirement(
    "GS-A_4367#6",
    "GS-A_4368#5",
    sourceSpecification = "gemSpec_Krypt",
    rationale =
        "Random numbers are generated using the RNG of the health card." +
            "This generator fulfills BSI-TR-03116#3.4 PTG.2 required by gemSpec_COS#14.9.5.1",
)
fun HealthCardCommand.Companion.getRandomValues(length: Int) =
    HealthCardCommand(
        expectedStatus = getRandomValuesStatus,
        cla = CLA,
        ins = INS,
        p1 = NO_MEANING,
        p2 = NO_MEANING,
        ne = length,
    )