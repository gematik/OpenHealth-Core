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

package de.gematik.openhealth.crypto

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.JsExport

private val pemRegex = """^-----BEGIN (.*)-----(.*)-----END (.*)-----$""".toRegex()
private const val PEM_DATA_MAX_LENGTH_PER_LINE = 64

@JsExport
class Pem(
    val type: String,
    val data: ByteArray,
)

@OptIn(ExperimentalEncodingApi::class)
fun Pem.encodeToString(): String =
    buildString {
        appendLine("-----BEGIN $type-----")
        Base64.Default
            .encode(
                data,
            ).windowed(PEM_DATA_MAX_LENGTH_PER_LINE, PEM_DATA_MAX_LENGTH_PER_LINE, true)
            .forEach {
                appendLine(it)
            }
        appendLine("-----END $type-----")
    }

@OptIn(ExperimentalEncodingApi::class)
@JsExport
fun String.decodeToPem(): Pem {
    val match = pemRegex.find(this.replace("\n", "").trim())
    val (headerType, data, footerType) =
        requireNotNull(
            match?.destructured,
        ) { "Invalid PEM format" }
    require(headerType == footerType) { "Invalid PEM type format" }
    return Pem(headerType, Base64.Default.decode(data))
}
