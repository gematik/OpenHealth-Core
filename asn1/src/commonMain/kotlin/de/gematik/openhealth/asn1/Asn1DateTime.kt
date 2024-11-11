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

package de.gematik.openhealth.asn1

import kotlin.js.JsExport
import kotlin.math.abs

/**
 * Raw representation of an [Asn1Type.UTC_TIME].
 * If [offset] is `null` this indicates that the time is in UTC.
 */
@JsExport
data class Asn1UtcTime(
    val year: Int,
    val month: Int,
    val day: Int,
    val hour: Int,
    val minute: Int,
    val second: Int?,
    val offset: Asn1Offset.UtcOffset?,
)

/**
 * Raw representation of an [Asn1Type.GENERALIZED_TIME].
 * If [offset] is `null` this indicates that the time is in UTC.
 */
@JsExport
data class Asn1GeneralizedTime(
    val year: Int,
    val month: Int,
    val day: Int,
    val hour: Int,
    val minute: Int?,
    val second: Int?,
    val fractionOfSecond: Int?,
    val offset: Asn1Offset.GeneralizedOffset?,
)

/**
 * Raw representation of an ASN.1 time offset.
 */
@JsExport
sealed class Asn1Offset {
    /**
     * UTC offset in hours and minutes.
     */
    data class UtcOffset(
        val hours: Int,
        val minutes: Int,
    ) : Asn1Offset()

    /**
     * Generalized offset in hours and minutes.
     */
    data class GeneralizedOffset(
        val hours: Int,
        val minutes: Int,
    ) : Asn1Offset()
}

private val utcTimeRegex =
    Regex("""(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})""")
private val generalizedTimeRegex =
    Regex("""(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?""")

/**
 * Parses the offset string into an [Asn1Offset] object.
 *
 * The offset string can either be empty, indicating no offset, or it can be in the format
 * 'Z' for UTC or '+/-HHMM' for a specific time zone offset.
 */
private fun parseTimeZoneOrOffset(offset: String): Asn1Offset? =
    when {
        offset.isEmpty() || offset[0] == 'Z' -> null
        else -> {
            val sign = if (offset[0] == '-') -1 else 1
            Asn1Offset.UtcOffset(
                hours = offset.substring(1, 3).toInt() * sign,
                minutes = offset.substring(3, 5).toInt(),
            )
        }
    }

/**
 * Returns the [Asn1Offset] object as a string.
 */
private fun formatOffset(offset: Asn1Offset?): String =
    if (offset == null) {
        "Z"
    } else {
        val (hours, minutes) =
            when (offset) {
                is Asn1Offset.UtcOffset -> offset.hours to offset.minutes
                is Asn1Offset.GeneralizedOffset -> offset.hours to offset.minutes
            }
        val sign = if (hours < 0 || minutes < 0) "-" else "+"
        "$sign${abs(hours).toString()
            .padStart(2, '0')}${abs(minutes).toString()
            .padStart(2, '0')}"
    }

/**
 * Parses a UTC time string into an [Asn1UtcTime] object.
 */
private fun Asn1Decoder.ParserScope.parseUtcTime(value: String): Asn1UtcTime {
    val match = utcTimeRegex.find(value)
    val (yy, mm, dd, hh, min, ss, offset) =
        match?.destructured
            ?: fail { "Wrong utc time format: `$value`" }
    return Asn1UtcTime(
        year = yy.toInt(),
        month = mm.toInt(),
        day = dd.toInt(),
        hour = hh.toInt(),
        minute = min.toInt(),
        second = ss.takeIf { it.isNotEmpty() }?.toInt(),
        offset = parseTimeZoneOrOffset(offset) as? Asn1Offset.UtcOffset,
    )
}

/**
 * Parses an ASN.1 generalized time string.
 */
private fun Asn1Decoder.ParserScope.parseGeneralizedTime(value: String): Asn1GeneralizedTime {
    val match = generalizedTimeRegex.find(value)
    val (yyyy, mm, dd, hh, min, ss, fff, offset) =
        match?.destructured
            ?: fail { "Wrong generalized time format: `$value`" }
    return Asn1GeneralizedTime(
        year = yyyy.toInt(),
        month = mm.toInt(),
        day = dd.toInt(),
        hour = hh.toInt(),
        minute = min.takeIf { it.isNotEmpty() }?.toInt(),
        second = ss.takeIf { it.isNotEmpty() }?.toInt(),
        fractionOfSecond = fff.takeIf { it.isNotEmpty() }?.substring(1)?.toInt(),
        offset = parseTimeZoneOrOffset(offset) as? Asn1Offset.GeneralizedOffset,
    )
}

/**
 * Read [Asn1Type.UTC_TIME].
 */
@JsExport
fun Asn1Decoder.ParserScope.readUtcTime(): Asn1UtcTime =
    advanceWithTag(Asn1Type.UTC_TIME) {
        val value = readBytes(remainingLength).decodeToString()
        parseUtcTime(value)
    }

/**
 * Read [Asn1Type.GENERALIZED_TIME].
 */
@JsExport
fun Asn1Decoder.ParserScope.readGeneralizedTime(): Asn1GeneralizedTime =
    advanceWithTag(Asn1Type.GENERALIZED_TIME) {
        val value = readBytes(remainingLength).decodeToString()
        parseGeneralizedTime(value)
    }

/**
 * Write [Asn1Type.UTC_TIME].
 */
@JsExport
fun Asn1Encoder.WriterScope.writeUtcTime(value: Asn1UtcTime) {
    writeTaggedObject(Asn1Type.UTC_TIME) {
        val formattedTime =
            buildString {
                append(
                    value.year
                        .rem(100)
                        .toString()
                        .padStart(2, '0'),
                )
                append(value.month.toString().padStart(2, '0'))
                append(value.day.toString().padStart(2, '0'))
                append(value.hour.toString().padStart(2, '0'))
                append(value.minute.toString().padStart(2, '0'))
                value.second?.let {
                    append(it.toString().padStart(2, '0'))
                }
                append(formatOffset(value.offset))
            }
        write(formattedTime.encodeToByteArray())
    }
}

/**
 * Write [Asn1Type.GENERALIZED_TIME].
 */
@JsExport
fun Asn1Encoder.WriterScope.writeGeneralizedTime(value: Asn1GeneralizedTime) {
    writeTaggedObject(Asn1Type.GENERALIZED_TIME) {
        val formattedTime =
            buildString {
                append(value.year.toString().padStart(4, '0'))
                append(value.month.toString().padStart(2, '0'))
                append(value.day.toString().padStart(2, '0'))
                append(value.hour.toString().padStart(2, '0'))
                value.minute?.let { append(it.toString().padStart(2, '0')) }
                value.second?.let { append(it.toString().padStart(2, '0')) }
                value.fractionOfSecond?.let {
                    append(".${it.toString().padStart(1, '0')}")
                }
                append(formatOffset(value.offset))
            }
        write(formattedTime.encodeToByteArray())
    }
}
