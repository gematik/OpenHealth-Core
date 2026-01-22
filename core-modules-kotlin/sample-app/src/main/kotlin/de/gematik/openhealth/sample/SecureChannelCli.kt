// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package de.gematik.openhealth.sample

import de.gematik.openhealth.healthcard.ApduException
import de.gematik.openhealth.healthcard.CardAccessNumber
import de.gematik.openhealth.healthcard.CommandApdu
import de.gematik.openhealth.healthcard.SecureChannelException
import de.gematik.openhealth.healthcard.establishSecureChannel
import javax.smartcardio.Card
import javax.smartcardio.CardTerminals
import javax.smartcardio.TerminalFactory
import kotlin.collections.joinToString

/**
 * Minimal demonstration that wires the secure channel implementation into the PC/SC stack.
 *
 * You need to provide the card access number via the `CARD_ACCESS_NUMBER` environment variable
 * (or the `-DcardAccessNumber=...` JVM property).
 */
fun main() {
    val cardAccessNumber = System.getProperty("cardAccessNumber")
        ?: System.getenv("CARD_ACCESS_NUMBER")
        ?: error("Provide CARD_ACCESS_NUMBER env variable or -DcardAccessNumber=XXXXXX")
    val apdu = byteArrayOf(0x00, 0x84.toByte(), 0x00, 0x00, 0x08) // GET CHALLENGE default
    val can = try {
        CardAccessNumber.fromDigits(cardAccessNumber)
    } catch (ex: SecureChannelException) {
        error("Invalid CAN: ${ex.message}")
    }

    val card = openPcscCard()
    try {
        val secureChannel = establishSecureChannel(PcscCardChannel(card.basicChannel), can)
        println("Secure channel established.")
        val command = try {
            CommandApdu.fromBytes(apdu)
        } catch (ex: ApduException) {
            error("Failed to build command APDU: ${ex.message}")
        }
        val response = secureChannel.transmit(command)
        val sw = "%04X".format(response.sw().toInt())
        println("Secure channel response: SW=$sw, data=${response.data().toHexString()}")
    } finally {
        try {
            card.disconnect(false)
        } catch (_: Exception) {
            // Ignore disconnect errors
        }
    }
}

private fun openPcscCard(): Card {
    val factory = TerminalFactory.getDefault()
    val terminals: CardTerminals = factory.terminals()
    val available = terminals.list().ifEmpty {
        error("No connected smart-card terminals found.")
    }
    val index = System.getProperty("pcsc.terminal")?.toIntOrNull() ?: 0
    require(index in available.indices) {
        "Terminal index $index is out of bounds. Available terminals: ${available.map { it.name }}"
    }
    val terminal = available[index]
    println("Using terminal '${terminal.name}' to open a card session.")
    return terminal.connect("*")
}

private fun ByteArray.toHexString(): String =
    joinToString(separator = " ") { eachByte -> "%02X".format(eachByte) }

private fun hexToBytes(value: String): ByteArray {
    val sanitized = value.replace("\\s".toRegex(), "")
    require(sanitized.length % 2 == 0) { "Hex string must have an even length." }
    return sanitized.chunked(2)
        .map { chunk -> chunk.toInt(16).toByte() }
        .toByteArray()
}
