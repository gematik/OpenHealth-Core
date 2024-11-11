package de.gematik.kmp.asn1

import kotlin.js.JsExport

@JsExport
object Asn1Type {
    const val Boolean = 0x01
    const val Integer = 0x02
    const val BitString = 0x03
    const val OctetString = 0x04
    const val Null = 0x05
    const val ObjectIdentifier = 0x06
    const val ObjectDescriptor = 0x07
    const val External = 0x08
    const val Real = 0x09
    const val Enumerated = 0x0A
    const val EmbeddedPdv = 0x0B
    const val Utf8String = 0x0C
    const val RelativeOid = 0x0D
    const val Time = 0x0E
    const val Sequence = 0x10
    const val Set = 0x11
    const val NumericString = 0x12
    const val PrintableString = 0x13
    const val TeletexString = 0x14
    const val VideotexString = 0x15
    const val Ia5String = 0x16
    const val UtcTime = 0x17
    const val GeneralizedTime = 0x18
    const val GraphicString = 0x19
    const val VisibleString = 0x1A
    const val GeneralString = 0x1B
    const val UniversalString = 0x1C
    const val CharacterString = 0x1D
    const val BmpString = 0x1E
    const val Date = 0x1F
    const val TimeOfDay = 0x20
    const val DateTime = 0x21
    const val Duration = 0x22
}

/**
 * Marks a tag constructed.
 */
@JsExport
fun Int.asConstructedTag(): Int = this or 0x20

/**
 * Marks a tag as application.
 */
@JsExport
fun Int.asApplicationTag(): Int = this or 0x40

/**
 * Marks a tag as context specific.
 */
@JsExport
fun Int.asContextSpecificTag(): Int = this or 0x80

/**
 * Marks a tag private.
 */
@JsExport
fun Int.asPrivateTag(): Int = this or 0xC0