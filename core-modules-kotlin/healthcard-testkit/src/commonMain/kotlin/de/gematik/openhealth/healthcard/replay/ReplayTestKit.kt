// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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

package de.gematik.openhealth.healthcard.replay

import de.gematik.openhealth.healthcard.HealthCardResponseStatus
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class Transcript(
    val supportsExtendedLength: Boolean,
    val can: String,
    val keys: List<String>,
    val exchanges: List<ExchangeEntry>,
)

data class ExchangeEntry(
    val tx: String,
    val rx: String,
)

data class ResponseApduParts(
    val sw: UShort,
    val data: ByteArray,
)

class ReplayChannelCore(
    private val supportsExtendedLength: Boolean,
    exchanges: List<ExchangeEntry>,
) {
    private val entries = ArrayDeque(exchanges)

    fun supportsExtendedLength(): Boolean = supportsExtendedLength

    fun transmit(commandBytes: ByteArray): ResponseApduParts {
        val entry = entries.removeFirstOrNull() ?: error("replay exhausted")
        val txHex = commandBytes.toHexString()
        if (txHex != entry.tx) {
            error("replay mismatch: expected ${entry.tx} got $txHex")
        }
        val rxBytes = hexToBytes(entry.rx)
        require(rxBytes.size >= 2) { "response APDU too short" }
        val sw = (((rxBytes[rxBytes.size - 2].toInt() and 0xFF) shl 8) or (rxBytes[rxBytes.size - 1].toInt() and 0xFF))
            .toUShort()
        val data = rxBytes.copyOfRange(0, rxBytes.size - 2)
        return ResponseApduParts(sw = sw, data = data)
    }
}

enum class VerifyPinOutcome {
    SUCCESS,
    WRONG_SECRET_WARNING,
    CARD_BLOCKED,
}

enum class CertificateFile {
    CH_AUT_E256,
    EGK_AUT_CVC_E256,
}

private val json = Json { ignoreUnknownKeys = true }

fun transcriptFromJsonl(jsonl: String): Transcript {
    var header: JsonObject? = null
    val exchanges = mutableListOf<ExchangeEntry>()

    for (line in jsonl.lineSequence().filter { it.isNotBlank() }) {
        val entry = json.parseToJsonElement(line).jsonObject
        when (entry["type"]?.jsonPrimitive?.content) {
            "header" -> header = entry
            "exchange" -> {
                val tx = entry["tx"]?.jsonPrimitive?.content ?: error("missing tx")
                val rx = entry["rx"]?.jsonPrimitive?.content ?: error("missing rx")
                exchanges.add(ExchangeEntry(tx, rx))
            }
        }
    }

    val headerEntry = header ?: error("missing header")
    val supportsExtendedLength = headerEntry["supports_extended_length"]?.jsonPrimitive?.booleanOrNull
        ?: error("missing supports_extended_length")
    val can = headerEntry["can"]?.jsonPrimitive?.content ?: error("missing can")
    val keys = headerEntry["keys"]?.jsonArray?.map { it.jsonPrimitive.content } ?: error("missing keys")
    return Transcript(supportsExtendedLength, can, keys, exchanges)
}

fun ByteArray.toHexString(): String =
    joinToString(separator = "") { eachByte -> "%02X".format(eachByte) }

fun hexToBytes(value: String): ByteArray {
    require(value.length % 2 == 0) { "hex string must have an even length" }
    return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

expect class SecureChannelHandle {
    fun verifyPin(pin: String): VerifyPinOutcome
    fun getRandom(length: UInt): ByteArray
    fun readVsd(): ByteArray
    fun retrieveCertificate(): ByteArray
    fun retrieveCertificateFrom(certificate: CertificateFile): ByteArray
    fun unlockEgkWithPuk(puk: String): HealthCardResponseStatus
    fun changePinWithPuk(puk: String, newPin: String): HealthCardResponseStatus
}

expect fun establishReplaySecureChannel(transcript: Transcript): SecureChannelHandle
