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
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import org.bouncycastle.jce.ECNamedCurveTable

internal actual fun EcPoint.nativeTimes(k: BigInteger): EcPoint {
    val ecSpec = ECNamedCurveTable.getParameterSpec(curve.name)
    val ecPoint = ecSpec.curve.decodePoint(uncompressed)
    val result = ecPoint.multiply(k.toJavaBigInteger())
    val uncompressedEcPoint = result.getEncoded(false)
    return EcPublicKey(curve, uncompressedEcPoint).toEcPoint()
}

internal actual fun EcPoint.nativePlus(other: EcPoint): EcPoint {
    val ecSpec = ECNamedCurveTable.getParameterSpec(curve.name)
    val ecPoint = ecSpec.curve.decodePoint(uncompressed)
    val otherEcPoint = ecSpec.curve.decodePoint(other.uncompressed)
    val result = ecPoint.add(otherEcPoint)
    val uncompressedEcPoint = result.getEncoded(false)
    return EcPublicKey(curve, uncompressedEcPoint).toEcPoint()
}
