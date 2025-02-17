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

import de.gematik.openhealth.smartcard.identifier.ShortFileIdentifier

private const val CLA = 0x00
private const val INS = 0xB0
private const val BYTE_MODULO = 256
private const val SFI_MARKER = 0x80
private const val MIN_OFFSET_RANGE = 0
private const val MAX_OFFSET_WITHOUT_SFI_RANGE = 0x7FFF
private const val MAX_OFFSET_WITH_SFI_RANGE = 255

/**
 * Commands representing the Read Binary command in gemSpec_COS#14.3.2
 */

/**
 * Creates a [HealthCardCommand] for the READ BINARY command without offset.
 * (gemSpec_COS#14.3.2)
 */
@Suppress("ktlint:standard:no-consecutive-comments")
fun HealthCardCommand.Companion.read(): HealthCardCommand =
    HealthCardCommand.read(0x00, EXPECT_ALL_WILDCARD)

/**
 * Creates a[HealthCardCommand] for the READ BINARY command.
 * (gemSpec_COS#14.3.2)
 *
 * @param offset The offset from which to read.
 */
fun HealthCardCommand.Companion.read(offset: Int) =
    HealthCardCommand.read(offset, EXPECT_ALL_WILDCARD)

/**
 * Creates a [HealthCardCommand] for the READ BINARY command without ShortFileIdentifier.
 * (gemSpec_COS#14.3.2.1)
 *
 * @param offset The offset from which to read.
 * @param ne The maximum number of bytes to read.
 */
fun HealthCardCommand.Companion.read(
    offset: Int,
    ne: Int,
): HealthCardCommand {
    require(offset in MIN_OFFSET_RANGE..MAX_OFFSET_WITHOUT_SFI_RANGE)

    val p2 = offset % BYTE_MODULO
    val p1 = (offset - p2) / BYTE_MODULO

    return HealthCardCommand(
        expectedStatus = readStatus,
        cla = CLA,
        ins = INS,
        p1 = p1,
        p2 = p2,
        ne = ne,
    )
}

/**
 * Creates a [HealthCardCommand] for the READ BINARY command with ShortFileIdentifier.
 * (gemSpec_COS#14.3.2.2)
 *
 * @param sfi The ShortFileIdentifier.
 */
fun HealthCardCommand.Companion.read(sfi: ShortFileIdentifier) =
    HealthCardCommand.read(sfi, 0x00, EXPECT_ALL_WILDCARD)

/**
 * Creates a [HealthCardCommand] for the READ BINARY command with ShortFileIdentifier.
 * (gemSpec_COS#14.3.2.2)
 *
 * @param sfi The ShortFileIdentifier.
 * @param offset The offset from which to read.
 */
fun HealthCardCommand.Companion.read(
    sfi: ShortFileIdentifier,
    offset: Int,
) = HealthCardCommand.read(sfi, offset, EXPECT_ALL_WILDCARD)

/**
 * Creates a [HealthCardCommand] for the READ BINARY command with ShortFileIdentifier.
 * (gemSpec_COS#14.3.2.2)
 *
 * @param sfi The ShortFileIdentifier.
 * @param offset The offset from which to read.
 * @param ne The maximum number of bytes to read.
 */
fun HealthCardCommand.Companion.read(
    sfi: ShortFileIdentifier,
    offset: Int,
    ne: Int,
): HealthCardCommand {
    require(offset in MIN_OFFSET_RANGE..MAX_OFFSET_WITH_SFI_RANGE)

    return HealthCardCommand(
        expectedStatus = readStatus,
        cla = CLA,
        ins = INS,
        p1 = SFI_MARKER + sfi.sfId,
        p2 = offset,
        ne = ne,
    )
}
