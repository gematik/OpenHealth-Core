package de.gematik.openhealth.smartcard.exchange

import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.HealthCardResponseStatus
import de.gematik.openhealth.smartcard.command.read
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier
import de.gematik.openhealth.smartcard.identifier.FileIdentifier

/**
 * Reads the insurance data (VD) from the EF.VD file located in the DF.HCA directory of the eGK.
 *
 * The process includes:
 * 1. Selecting the root directory (MF) to ensure a clean context.
 * 2. Selecting the DF.HCA application using its AID (gemSpecObjSys, Section 5.4).
 * 3. Selecting the EF.VD file within the DF.HCA directory (gemSpecObjSys, Section 5.4.9).
 * 4. Reading the VD data incrementally (gemSpecCos, Sections 10.3.3 and 10.4.2).
 *
 * @return The complete VD data as a byte array.
 */
suspend fun TrustedChannelScope.readVsd(): ByteArray {
    HealthCardCommand.select(selectParentElseRoot = false, readFirst = false).transmitSuccessfully()

    HealthCardCommand.select(ApplicationIdentifier(Mf.Df.HCA.AID)).transmitSuccessfully()

    // 5.4.9 MF / DF.HCA / EF.VD This file contains the VD of the cardholder.

    HealthCardCommand.select(
        FileIdentifier(Mf.Df.HCA.Ef.Vd.FID),
        selectDfElseEf = false
    ).transmitSuccessfully()

    var buffer = byteArrayOf()
    var offset = 0
    while (true) {
        val response = HealthCardCommand.read(offset)
            .transmit()

        val data = response.apdu.data

        if (data.isNotEmpty()) {
            buffer += data
            offset += data.size
        }

        when (response.status) {
            HealthCardResponseStatus.SUCCESS -> {}
            HealthCardResponseStatus.END_OF_FILE_WARNING,
            HealthCardResponseStatus.OFFSET_TOO_BIG -> break

            else -> error("Couldn't read vsd: ${response.status}")
        }
    }
    return buffer
}