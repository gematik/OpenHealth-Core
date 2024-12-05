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

package de.gematik.kmp.smartcard.command

import de.gematik.kmp.smartcard.identifier.ShortFileIdentifier

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
 * Calls ReadCommand(0x00, EXPECT_ALL_WILDCARD)
 */
fun HealthCardCommand.Companion.read() = HealthCardCommand.read(0x00, EXPECT_ALL_WILDCARD)

/**
 * Calls ReadCommand(offset, EXPECT_ALL_WILDCARD)
 */
fun HealthCardCommand.Companion.read(offset: Int) =
    HealthCardCommand.read(offset, EXPECT_ALL_WILDCARD)

/**
 * Use case Read Binary without ShortFileIdentifier gemSpec_COS#14.3.2.1
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
 * Calls ReadCommand(sfi, 0x00, EXPECT_ALL_WILDCARD)
 */
fun HealthCardCommand.Companion.read(sfi: ShortFileIdentifier) =
    HealthCardCommand.read(sfi, 0x00, EXPECT_ALL_WILDCARD)

/**
 * Calls ReadCommand(sfi, offset, EXPECT_ALL_WILDCARD)
 */
fun HealthCardCommand.Companion.read(
    sfi: ShortFileIdentifier,
    offset: Int,
) = HealthCardCommand.read(sfi, offset, EXPECT_ALL_WILDCARD)

/**
 * Use case Read Binary with ShortFileIdentifier gemSpec_COS#14.3.2.2
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