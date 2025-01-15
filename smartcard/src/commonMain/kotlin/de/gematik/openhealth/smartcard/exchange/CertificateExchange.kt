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

package de.gematik.openhealth.smartcard.exchange

import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.cardobjects.Df
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_EXTENDED
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.ResponseStatus
import de.gematik.openhealth.smartcard.command.executeSuccessfulOn
import de.gematik.openhealth.smartcard.command.read
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier
import de.gematik.openhealth.smartcard.identifier.FileIdentifier

fun SmartCard.CommunicationScope.retrieveCertificate(): ByteArray {
    HealthCardCommand
        .select(
            ApplicationIdentifier(Df.Esign.AID),
        ).executeSuccessfulOn(this)
    HealthCardCommand
        .select(
            FileIdentifier(
                Mf.Df.Esign.Ef.CchAutE256.FID,
            ),
            selectDfElseEf = false,
            requestFcp = true,
            fcpLength = EXPECTED_LENGTH_WILDCARD_EXTENDED,
        ).executeSuccessfulOn(this)

    var buffer = byteArrayOf()
    var offset = 0
    while (true) {
        val response =
            HealthCardCommand
                .read(offset)
                .executeOn(this)

        val data = response.apdu.data

        if (data.isNotEmpty()) {
            buffer += data
            offset += data.size
        }

        when (response.status) {
            ResponseStatus.SUCCESS -> { }
            ResponseStatus.END_OF_FILE_WARNING,
            ResponseStatus.OFFSET_TOO_BIG,
            -> break
            else -> error("Couldn't read certificate: ${response.status}")
        }
    }

    return buffer
}