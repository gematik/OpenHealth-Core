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

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier
import de.gematik.openhealth.smartcard.identifier.FileIdentifier

private const val CLA = 0x00
private const val INS = 0xA4
private const val SELECTION_MODE_DF_BY_FID = 0x01
private const val SELECTION_MODE_EF_BY_FID = 0x02
private const val SELECTION_MODE_PARENT = 0x03
private const val SELECTION_MODE_AID = 0x04
private const val RESPONSE_TYPE_NO_RESPONSE = 0x0C
private const val RESPONSE_TYPE_FCP = 0x04
private const val FILE_OCCURRENCE_FIRST = 0x00
private const val FILE_OCCURRENCE_NEXT = 0x02
private const val P2_FCP = 0x04
private const val P2 = 0x0C

private fun calculateP2(
    requestFCP: Boolean,
    nextOccurrence: Boolean,
): Int =
    if (requestFCP) {
        RESPONSE_TYPE_FCP
    } else {
        RESPONSE_TYPE_NO_RESPONSE
    } +
        if (nextOccurrence) {
            FILE_OCCURRENCE_NEXT
        } else {
            FILE_OCCURRENCE_FIRST
        }

/**
 * Creates a [HealthCardCommand] for the SELECT command to select the root
 * of the object system or the parent folder.
 * (gemSpec_COS#14.2.6.1, gemSpec_COS#14.2.6.11, gemSpec_COS#14.2.6.2)
 *
 * @param selectParentElseRoot If true, selects the parent folder; otherwise, selects the root of the object system.
 * @param readFirst If true, requests the File Control Parameter (FCP); otherwise, only selects.
 */
fun HealthCardCommand.Companion.select(
    selectParentElseRoot: Boolean,
    readFirst: Boolean,
) = HealthCardCommand(
    expectedStatus = selectStatus,
    cla = CLA,
    ins = INS,
    p1 = if (selectParentElseRoot) SELECTION_MODE_PARENT else SELECTION_MODE_AID,
    p2 = calculateP2(readFirst, false),
    ne = if (readFirst) EXPECT_ALL_WILDCARD else null,
)

/**
 * Creates a [HealthCardCommand] for the SELECT command to select a file with an
 * Application Identifier (AID), first occurrence, without File Control Parameter.
 * (gemSpec_COS#14.2.6.5)
 *
 * @param aid The Application Identifier.
 */
fun HealthCardCommand.Companion.select(aid: ApplicationIdentifier) =
    HealthCardCommand.select(
        aid,
        selectNextElseFirstOccurrence = false,
        requestFcp = false,
        fcpLength = 0,
    )

/**
 * Creates a [HealthCardCommand] for the SELECT command to select a file with an
 * Application Identifier (AID).
 * (gemSpec_COS#14.2.6.5 - 14.2.6.8)
 *
 * @param aid The Application Identifier.
 * @param selectNextElseFirstOccurrence If true, selects the next occurrence;
 * otherwise, selects the first occurrence.
 * @param requestFcp If true, requests the File Control Parameter (FCP).
 * @param fcpLength Determines the expected size of the response if
 * the File Control Parameter is requested.
 */
fun HealthCardCommand.Companion.select(
    aid: ApplicationIdentifier,
    selectNextElseFirstOccurrence: Boolean,
    requestFcp: Boolean,
    fcpLength: Int,
) = HealthCardCommand(
    expectedStatus = selectStatus,
    cla = CLA,
    ins = INS,
    p1 = SELECTION_MODE_AID,
    p2 = calculateP2(requestFcp, selectNextElseFirstOccurrence),
    data = aid.aid,
    ne = if (requestFcp) fcpLength else null,
)

/**
 * Creates a [HealthCardCommand] for the SELECT command to select a DF or EF with a
 * File Identifier (FID).
 * (gemSpec_COS#14.2.6.9, gemSpec_COS#14.2.6.13)
 *
 * @param fid The File Identifier.
 * @param selectDfElseEf If true, selects a Dedicated File (DF);
 * otherwise, selects an Elementary File (EF).
 */
fun HealthCardCommand.Companion.select(
    fid: FileIdentifier,
    selectDfElseEf: Boolean,
) = HealthCardCommand.select(fid, selectDfElseEf, false, 0)

/**
 * Creates a [HealthCardCommand] for the SELECT command to select a DF or EF with a
 * File Identifier (FID).
 * (gemSpec_COS#14.2.6.9 - 14.2.6.10, gemSpec_COS#14.2.6.13 - 14.2.6.14)
 *
 * @param fid The File Identifier.
 * @param selectDfElseEf If true, selects a Dedicated File (DF);
 * otherwise, selects an Elementary File (EF).
 * @param requestFcp If true, requests the File Control Parameter (FCP).
 * @param fcpLength Determines the expected size of the response if
 * the File Control Parameter is requested.
 */
fun HealthCardCommand.Companion.select(
    fid: FileIdentifier,
    selectDfElseEf: Boolean,
    requestFcp: Boolean,
    fcpLength: Int,
) = HealthCardCommand(
    expectedStatus = selectStatus,
    cla = CLA,
    ins = INS,
    p1 = if (selectDfElseEf) SELECTION_MODE_DF_BY_FID else SELECTION_MODE_EF_BY_FID,
    p2 = if (requestFcp) P2_FCP else P2,
    data = fid.getFid(),
    ne = if (requestFcp) fcpLength else null,
)
