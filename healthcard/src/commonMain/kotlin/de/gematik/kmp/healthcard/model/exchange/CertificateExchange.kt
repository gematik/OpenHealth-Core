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



package de.gematik.kmp.healthcard.model.exchange

import de.gematik.kmp.healthcard.model.card.ICardChannel
import de.gematik.kmp.healthcard.model.cardobjects.Df
import de.gematik.kmp.healthcard.model.command.ResponseStatus
import de.gematik.kmp.healthcard.model.command.executeSuccessfulOn
import de.gematik.kmp.healthcard.model.command.read
import de.gematik.kmp.healthcard.model.command.select
import de.gematik.kmp.healthcard.model.identifier.ApplicationIdentifier
import de.gematik.kmp.healthcard.model.identifier.FileIdentifier

suspend fun ICardChannel.retrieveCertificate(): ByteArray {
    de.gematik.kmp.healthcard.model.command.HealthCardCommand
        .select(
            ApplicationIdentifier(Df.Esign.AID),
        ).executeSuccessfulOn(this)
    de.gematik.kmp.healthcard.model.command.HealthCardCommand
        .select(
            FileIdentifier(
                de.gematik.kmp.healthcard.model.cardobjects.Mf.Df.Esign.Ef.CchAutE256.FID,
            ),
            selectDfElseEf = false,
            requestFcp = true,
            fcpLength = de.gematik.kmp.healthcard.model.command.EXPECTED_LENGTH_WILDCARD_EXTENDED,
        ).executeSuccessfulOn(this)

    var buffer = byteArrayOf()
    var offset = 0
    while (true) {
        val response =
            de.gematik.kmp.healthcard.model.command.HealthCardCommand
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