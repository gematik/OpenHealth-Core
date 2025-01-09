/*
 * Copyright (c) 2025 gematik GmbH
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

package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.UnoptimizedCryptoApi

/**
 * Represents a point on an elliptic curve.
 *
 * An EC point is defined by its coordinates ([x], [y]) and the elliptic curve it belongs to.
 * It can also represent the point at infinity, which is denoted by having both x and y coordinates as null.
 *
 * The [x] and [y] coordinates are not verified to lie on the specified [curve].
 *
 * [EcPoint] provides basic operations for EC points, such as addition, doubling, and negation.
 *
 * @property curve the elliptic curve this point belongs to.
 * @property x the x-coordinate of the point, or null if it is at infinity.
 * @property y the y-coordinate of the point, or null if it is at infinity.
 *
 * @throws IllegalArgumentException If x and y are not both null or not null.
 */
@ExperimentalCryptoApi
data class EcPoint(
    val curve: EcCurve,
    val x: BigInteger?,
    val y: BigInteger?,
) {
    init {
        require((x == null && y == null) || (x != null && y != null)) {
            "X and Y must be both null or not null"
        }
    }

    /**
     * Returns the uncompressed representation of the EC point.
     *
     * The uncompressed representation consists of a leading byte (0x04) followed by the X coordinate and the Y coordinate, both as big-endian integers.
     *
     * The length of the returned byte array is always 65 bytes:
     * - 1 byte for the prefix (0x04)
     * - 32 bytes for the X coordinate
     * - 32 bytes for the Y coordinate
     *
     * @throws IllegalArgumentException if the EC point is at infinity, as it cannot be represented in uncompressed form.
     */
    val uncompressed: ByteArray get() =
        ByteArray(65).apply {
            require(
                !isInfinity,
            ) { "Can't encode infinite ec point to its uncompressed representation" }
            y!!.toByteArray().copyInto(this, 33)
            x!!.toByteArray().copyInto(this, 1)
            this[0] = 0x04
        }

    /**
     * Returns `true` if this represents an infinite point, i.e., both x and y coordinates are null.
     */
    val isInfinity: Boolean get() = x == null && y == null

    operator fun plus(other: EcPoint): EcPoint = nativePlus(other)

    operator fun times(k: BigInteger): EcPoint = nativeTimes(k)

    fun negate(): EcPoint = if (isInfinity) this else curve.point(x, (curve.p - y!!).mod(curve.p))
}

internal expect fun EcPoint.nativeTimes(k: BigInteger): EcPoint
internal expect fun EcPoint.nativePlus(other: EcPoint): EcPoint

@ExperimentalCryptoApi
fun EcPoint.toEcPublicKey(): EcPublicKey = EcPublicKey(curve, uncompressed)