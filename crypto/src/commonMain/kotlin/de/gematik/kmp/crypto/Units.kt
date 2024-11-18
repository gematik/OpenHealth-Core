package de.gematik.kmp.crypto

import kotlin.jvm.JvmInline

/**
 * Represents a unit of byte measurement.
 */
@JvmInline
@ExperimentalCryptoApi
value class ByteUnit(
    val value: Int,
)

/**
 * Returns a [ByteUnit] instance representing the specified number of bytes.
 */
@ExperimentalCryptoApi
val Int.bytes: ByteUnit get() = ByteUnit(this)

/**
 * Returns a [ByteUnit] instance representing the specified number of bits.
 */
@ExperimentalCryptoApi
val Int.bits: ByteUnit get() =
    if (this % 8 ==
        0
    ) {
        ByteUnit(this / 8)
    } else {
        error("Value must be multiple of 8")
    }

/**
 * Returns the number of bits in this byte unit.
 */
@ExperimentalCryptoApi
val ByteUnit.bits get() = value * 8

/**
 * Returns the number of bytes represented by this [ByteUnit] instance.
 * This is simply the underlying `value` of the enum.
 */
@ExperimentalCryptoApi
val ByteUnit.bytes get() = value