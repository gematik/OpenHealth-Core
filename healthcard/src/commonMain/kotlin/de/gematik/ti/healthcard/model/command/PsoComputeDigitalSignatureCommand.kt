

package de.gematik.ti.healthcard.model.command

private const val CLA = 0x00
private const val INS = 0x2A

/**
 * Commands representing Compute Digital Signature in gemSpec_COS#14.8.2
 */
fun HealthCardCommand.Companion.psoComputeDigitalSignature(dataToBeSigned: ByteArray) =
    HealthCardCommand(
        expectedStatus = psoComputeDigitalSignatureStatus,
        cla = CLA,
        ins = INS,
        p1 = 0x9E,
        p2 = 0x9A,
        data = dataToBeSigned,
        ne = EXPECT_ALL_WILDCARD,
    )