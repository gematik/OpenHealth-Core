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

package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray
import de.gematik.openhealth.crypto.wrapper.DeferScope
import de.gematik.openhealth.crypto.wrapper.deferred
import de.gematik.openhealth.crypto.wrapper.lazyDeferred
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toUint8Vector
import de.gematik.openhealth.crypto.internal.interop.EcPoint as JniEcPoint

private class JvmEcPoint(
    private val curve: EcCurve,
    private val uncompressed: ByteArray,
) : DeferScope by deferred() {
    private val ecPoint by lazyDeferred {
        JniEcPoint.create(curve.curveName(), uncompressed.toUint8Vector().alsoDefer())
    }

    fun times(k: BigInteger): EcPoint =
        runWithProvider {
            val uncompressedEcPoint =
                ecPoint
                    .times(
                        k.toTwosComplementByteArray().toUint8Vector().alsoDefer(),
                    ).uncompressed()
            EcPublicKey(curve, uncompressedEcPoint.toByteArray()).toEcPoint()
        }

    fun plus(other: JvmEcPoint): EcPoint =
        runWithProvider {
            val uncompressedEcPoint = ecPoint.add(other.ecPoint).uncompressed()
            EcPublicKey(curve, uncompressedEcPoint.toByteArray()).toEcPoint()
        }
}

internal actual fun EcPoint.nativeTimes(k: BigInteger): EcPoint =
    JvmEcPoint(curve, uncompressed).times(k)

internal actual fun EcPoint.nativePlus(other: EcPoint): EcPoint =
    JvmEcPoint(curve, uncompressed).plus(JvmEcPoint(other.curve, other.uncompressed))
