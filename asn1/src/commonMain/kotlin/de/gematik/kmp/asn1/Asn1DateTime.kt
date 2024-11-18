package de.gematik.kmp.asn1

import kotlin.js.JsExport
import kotlin.math.abs

/**
 * Raw representation of an [Asn1Type.UtcTime]. If [offset] is `null` this indicates that the time is in UTC.
 */
@JsExport
data class Asn1UtcTime(
    val year: Int,
    val month: Int,
    val day: Int,
    val hour: Int,
    val minute: Int,
    val second: Int?,
    val offset: Offset?,
) {
    /**
     * Optional offset from UTC. [hours] can be negative.
     */
    data class Offset(
        val hours: Int,
        val minutes: Int,
    )
}

private val utcTimeRegex =
    Regex("""(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})""")

/**
 * Read [Asn1Type.UtcTime].
 */
@JsExport
fun Asn1Decoder.ParserScope.readUtcTime(): Asn1UtcTime =
    advanceWithTag(Asn1Type.UtcTime) {
        val value = readBytes(remainingLength).decodeToString()
        val match = utcTimeRegex.find(value)
        val (yy, mm, dd, hh, min, ss, offset) =
            match?.destructured
                ?: fail { "Wrong utc time format: `$value`" }

        try {
            Asn1UtcTime(
                year = yy.toInt(),
                month = mm.toInt(),
                day = dd.toInt(),
                hour = hh.toInt(),
                minute = min.toInt(),
                second = ss.takeIf { it.isNotEmpty() }?.toInt(),
                offset =
                    when {
                        offset[0] == 'Z' -> null
                        else -> {
                            val sign = if (offset[0] == '-') -1 else 1
                            Asn1UtcTime.Offset(
                                hours = offset.substring(1, 3).toInt() * sign,
                                minutes = offset.substring(3, 5).toInt(),
                            )
                        }
                    },
            )
        } catch (e: NumberFormatException) {
            fail(e) { "Wrong utc time format: `$value`" }
        }
    }

@JsExport
fun Asn1Encoder.WriterScope.writeUtcTime(value: Asn1UtcTime) {
    writeTaggedObject(Asn1Type.UtcTime) {
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

                if (value.offset == null) {
                    append("Z")
                } else {
                    val sign = if (value.offset.hours < 0 || value.offset.minutes < 0) "-" else "+"
                    append(sign)
                    append(abs(value.offset.hours).toString().padStart(2, '0'))
                    append(abs(value.offset.minutes).toString().padStart(2, '0'))
                }
            }
        write(formattedTime.encodeToByteArray())
    }
}

/**
 * Raw representation of an [Asn1Type.GeneralizedTime]. If [offset] is `null` this indicates that the time is in UTC.
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
    val offset: Offset?,
) {
    /**
     * Optional offset from UTC. [hours] can be negative.
     */
    class Offset(
        val hours: Int,
        val minutes: Int,
    )
}

private val generalizedTimeRegex =
    Regex("""(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?""")

/**
 * Read [Asn1Type.GeneralizedTime].
 */
@JsExport
fun Asn1Decoder.ParserScope.readGeneralizedTime(): Asn1GeneralizedTime =
    advanceWithTag(Asn1Type.GeneralizedTime) {
        val value = readBytes(remainingLength).decodeToString()
        val match = generalizedTimeRegex.find(value)
        val (yyyy, mm, dd, hh, min, ss, fff, offset) =
            match?.destructured
                ?: fail { "Wrong generalized time format: `$value`" }

        try {
            Asn1GeneralizedTime(
                year = yyyy.toInt(),
                month = mm.toInt(),
                day = dd.toInt(),
                hour = hh.toInt(),
                minute = min.takeIf { it.isNotEmpty() }?.toInt(),
                second = ss.takeIf { it.isNotEmpty() }?.toInt(),
                fractionOfSecond = fff.takeIf { it.isNotEmpty() }?.substring(1)?.toInt(),
                offset =
                    when {
                        offset.isEmpty() -> null
                        offset[0] == 'Z' -> null
                        else -> {
                            val sign = if (offset[0] == '-') -1 else 1
                            Asn1GeneralizedTime.Offset(
                                hours = offset.substring(1, 3).toInt() * sign,
                                minutes = offset.substring(3, 5).toInt(),
                            )
                        }
                    },
            )
        } catch (e: NumberFormatException) {
            fail(e) { "Wrong generalized time format: `$value`" }
        }
    }

@JsExport
fun Asn1Encoder.WriterScope.writeGeneralizedTime(value: Asn1GeneralizedTime) {
    writeTaggedObject(Asn1Type.GeneralizedTime) {
        val formattedTime =
            buildString {
                append(value.year.toString().padStart(4, '0'))
                append(value.month.toString().padStart(2, '0'))
                append(value.day.toString().padStart(2, '0'))
                append(value.hour.toString().padStart(2, '0'))

                value.minute?.let {
                    append(it.toString().padStart(2, '0'))
                }

                value.second?.let {
                    append(it.toString().padStart(2, '0'))
                }

                value.fractionOfSecond?.let {
                    append(".")
                    append(it.toString().padStart(1, '0'))
                }

                if (value.offset == null) {
                    append("Z")
                } else {
                    val sign = if (value.offset.hours < 0 || value.offset.minutes < 0) "-" else "+"
                    append(sign)
                    append(abs(value.offset.hours).toString().padStart(2, '0'))
                    append(abs(value.offset.minutes).toString().padStart(2, '0'))
                }
            }
        write(formattedTime.encodeToByteArray())
    }
}