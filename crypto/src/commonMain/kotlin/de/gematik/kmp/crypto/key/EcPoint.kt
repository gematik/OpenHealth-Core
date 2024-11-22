/*
 * Copyright (c) 2024 gematik GmbH
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

package de.gematik.kmp.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

@ExperimentalCryptoApi
data class EcPoint(val curve: EcCurve, val x: BigInteger?, val y: BigInteger?) {
    init {
        require((x == null && y == null) || (x != null && y != null)) { "X and Y must be both null or not null" }
    }

    fun isInfinity(): Boolean = x == null && y == null

    operator fun plus(other: EcPoint): EcPoint {
        // O + P = P
        if (this.isInfinity()) return other

        // P + O = P
        if (other.isInfinity()) return this

        // P + P = 2P
        if (this == other) return this.dbl()

        // P + (-P) = O
        if (this.negate() == other) return curve.point(null, null)

        // P + Q where x1 = x2
        if (x == other.x) return curve.point(null, null)

        val dx = ((x!! - other.x!!) + curve.p).mod(curve.p)
        val dy = ((y!! - other.y!!) + curve.p).mod(curve.p)
        val lambda = (dy * dx.modInverse(curve.p)).mod(curve.p)
        val newX = (lambda * lambda - x - other.x).mod(curve.p)
        val newY = (lambda * (x - newX) - y).mod(curve.p)
        return curve.point(newX, newY)
    }

    fun dbl(): EcPoint {
        // Handle point at infinity
        if (this.isInfinity()) return this

        // 2P = O when y = 0
        if (y == BigInteger.ZERO) return curve.point(null, null)

//        val lambda = (BigInteger.fromInt(3) * x!! * x + curve.a) * (BigInteger.TWO * y!!).modInverse(curve.p)
//        val newX = (lambda * lambda - BigInteger.TWO * x).mod(curve.p)
//        val newY = (lambda * (x - newX) - y).mod(curve.p)
//
//        return curve.point(newX, newY)

        val lambda = ((BigInteger.fromInt(3) * x!! * x + curve.a) * (BigInteger.TWO * y!!).modInverse(curve.p)).mod(curve.p)
        val newX = (lambda * lambda - BigInteger.TWO * x).mod(curve.p)
        val newY = (lambda * (x - newX) - y).mod(curve.p)
        return curve.point(newX, newY)
    }

    operator fun times(k: BigInteger): EcPoint {
        if (k == BigInteger.ZERO) return curve.point(null, null) // Point at infinity
        val absK = k.abs()
        var current = this
        var result = curve.point(null, null) // Point at infinity

        var multiplier = absK
        while (multiplier > BigInteger.ZERO) {
            if (multiplier.and(BigInteger.ONE) == BigInteger.ONE) {
                result += current
            }
            current = current.dbl()
            multiplier = multiplier.shr(1)
        }

        // If k is negative, return the negation of the result
        return if (k < BigInteger.ZERO) result.negate() else result
    }

    fun negate(): EcPoint = if (isInfinity()) this else curve.point(x, (curve.p - y!!).mod(curve.p))
}
