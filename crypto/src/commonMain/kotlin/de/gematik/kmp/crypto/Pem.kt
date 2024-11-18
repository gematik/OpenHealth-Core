package de.gematik.kmp.crypto

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.JsExport

private val pemRegex = """^-----BEGIN (.*)-----(.*)-----END (.*)-----$""".toRegex()
private const val pemDataMaxLengthPerLine = 64

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
            ).windowed(pemDataMaxLengthPerLine, pemDataMaxLengthPerLine, true)
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