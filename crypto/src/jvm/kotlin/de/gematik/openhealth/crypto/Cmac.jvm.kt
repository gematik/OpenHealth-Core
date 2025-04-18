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

import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.wrapper.DeferScope
import de.gematik.openhealth.crypto.wrapper.deferred
import de.gematik.openhealth.crypto.wrapper.lazyDeferred
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toUint8Vector
import de.gematik.openhealth.crypto.internal.interop.Cmac as JniCmac

/**
* JVM implementation of the CMAC algorithm.
*/
private class JvmCmac(
    override val spec: CmacSpec,
    scope: CryptoScope,
    secret: SecretKey,
) : Cmac,
    DeferScope by deferred(scope) {
    init {
        require(spec.algorithm == CmacAlgorithm.Aes) { "Only AES is supported" }
    }

    private val cmac by lazyDeferred {
        JniCmac.create(secret.data.toUint8Vector().alsoDefer(), "AES-${secret.length.bits}-CBC")
    }

    /**
     * Updates the CMAC with the given data.
     */
    override fun update(data: ByteArray) {
        runWithProvider {
            cmac.update(data.toUint8Vector().alsoDefer())
        }
    }

    /**
     * Finalizes the CMAC computation and returns the resulting MAC.
     * Can only be called once.
     * @throws CmacException if called more than once
     */
    override fun final(): ByteArray =
        runWithProvider {
            cmac._final().toByteArray().alsoDefer()
        }
}

/**
 * JVM-specific implementation for creating CMAC instances.
 */
actual fun CmacSpec.nativeCreateCmac(
    scope: CryptoScope,
    secret: SecretKey,
): Cmac = JvmCmac(this, scope, secret)
