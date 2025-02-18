/*
 * Copyright 2025 gematik GmbH
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

import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.EXPECTED_LENGTH_WILDCARD_EXTENDED
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.HealthCardResponseStatus
import de.gematik.openhealth.smartcard.command.read
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier
import de.gematik.openhealth.smartcard.identifier.FileIdentifier

/**
 * Retrieves the X.509 certificate stored in the EF.C.CH.AUT.E256 file on the eGK.
 *
 * The process follows these steps:
 * 1. Selects the DF.ESIGN application using its AID (gemSpecObjSys, Section 5.5).
 * 2. Selects the EF.C.CH.AUT.E256 file using its FID (gemSpecObjSys, Section 5.5.9).
 * 3. Reads the certificate data incrementally from the file (gemSpecCos, Sections 10.3.3 and 10.4.2).
 *
 * @return The complete X.509 certificate as a byte array.
 */
suspend fun TrustedChannelScope.retrieveCertificate(): ByteArray {
    HealthCardCommand.select(ApplicationIdentifier(Mf.Df.Esign.AID)).transmitSuccessfully()
    HealthCardCommand
        .select(
            FileIdentifier(
                Mf.Df.Esign.Ef.CchAutE256.FID,
            ),
            selectDfElseEf = false,
            requestFcp = true,
            fcpLength = EXPECTED_LENGTH_WILDCARD_EXTENDED,
        ).transmitSuccessfully()

    var buffer = byteArrayOf()
    var offset = 0
    while (true) {
        val response =
            HealthCardCommand
                .read(offset)
                .transmit()

        val data = response.apdu.data

        if (data.isNotEmpty()) {
            buffer += data
            offset += data.size
        }

        when (response.status) {
            HealthCardResponseStatus.SUCCESS -> {}
            HealthCardResponseStatus.END_OF_FILE_WARNING,
            HealthCardResponseStatus.OFFSET_TOO_BIG,
            -> break

            else -> error("Couldn't read certificate: ${response.status}")
        }
    }

    return buffer
}
