/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.exchange

import de.gematik.ti.healthcard.model.card.ICardChannel
import de.gematik.ti.healthcard.model.cardobjects.Df
import de.gematik.ti.healthcard.model.command.ResponseStatus
import de.gematik.ti.healthcard.model.command.executeSuccessfulOn
import de.gematik.ti.healthcard.model.command.read
import de.gematik.ti.healthcard.model.command.select
import de.gematik.ti.healthcard.model.identifier.ApplicationIdentifier
import de.gematik.ti.healthcard.model.identifier.FileIdentifier

fun ICardChannel.retrieveCertificate(): ByteArray {
    de.gematik.ti.healthcard.model.command.HealthCardCommand.select(
        ApplicationIdentifier(Df.Esign.AID)
    ).executeSuccessfulOn(this)
    de.gematik.ti.healthcard.model.command.HealthCardCommand.select(
        FileIdentifier(de.gematik.ti.healthcard.model.cardobjects.Mf.Df.Esign.Ef.CchAutE256.FID),
        selectDfElseEf = false,
        requestFcp = true,
        fcpLength = de.gematik.ti.healthcard.model.command.EXPECTED_LENGTH_WILDCARD_EXTENDED
    ).executeSuccessfulOn(this)

    var buffer = byteArrayOf()
    var offset = 0
    while (true) {
        val response = de.gematik.ti.healthcard.model.command.HealthCardCommand.read(offset)
            .executeOn(this)

        val data = response.apdu.data

        if (data.isNotEmpty()) {
            buffer += data
            offset += data.size
        }

        when (response.status) {
            ResponseStatus.SUCCESS -> { }
            ResponseStatus.END_OF_FILE_WARNING,
            ResponseStatus.OFFSET_TOO_BIG -> break
            else -> error("Couldn't read certificate: ${response.status}")
        }
    }

    return buffer
}
