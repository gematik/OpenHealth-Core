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
