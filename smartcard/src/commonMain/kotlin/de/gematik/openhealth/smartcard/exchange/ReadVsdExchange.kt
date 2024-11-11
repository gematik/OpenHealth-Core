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

    HealthCardCommand
        .select(
            FileIdentifier(Mf.Df.HCA.Ef.Vd.FID),
            selectDfElseEf = false,
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

            else -> error("Couldn't read vsd: ${response.status}")
        }
    }
    return buffer
}
