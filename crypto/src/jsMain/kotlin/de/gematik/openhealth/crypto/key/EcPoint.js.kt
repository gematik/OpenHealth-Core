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
import de.gematik.openhealth.crypto.wrapper.Provider
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toByteArray
import de.gematik.openhealth.crypto.wrapper.toUint8Vector

internal actual fun EcPoint.nativeTimes(k: BigInteger): EcPoint =
    runWithProvider {
        val uncompressedEcPoint = ECPoint.create(curve.curveName(), uncompressed.toUint8Vector())
            .times(k.toByteArray().toUint8Vector()).uncompressed()
        EcPublicKey(curve, uncompressedEcPoint.toByteArray()).toEcPoint()
    }

internal actual fun EcPoint.nativePlus(other: EcPoint): EcPoint =
    runWithProvider {
        val uncompressedEcPoint = ECPoint.create(curve.curveName(), uncompressed.toUint8Vector())
            .plus(ECPoint.create(curve.curveName(), other.uncompressed.toUint8Vector()))
            .uncompressed()
        EcPublicKey(curve, uncompressedEcPoint.toByteArray()).toEcPoint()
    }