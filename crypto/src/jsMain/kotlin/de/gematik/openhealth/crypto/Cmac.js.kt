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

package de.gematik.openhealth.crypto

import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.wrapper.lazyWithProvider
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import js.typedarrays.toUint8Array

private class JsCmac(
    override val spec: CmacSpec,
    secret: SecretKey,
) : Cmac {
    init {
        require(spec.algorithm == CmacAlgorithm.Aes) { "Only AES is supported" }
    }

    private val cmac by lazyWithProvider {
        CMAC.create(fromUint8Array(secret.data.toUint8Array()), "AES-${secret.length.bits}-CBC");
    }

    override  fun update(data: ByteArray) {
        runWithProvider {
            cmac.update(fromUint8Array(data.toUint8Array()))
        }
    }

    override  fun final(): ByteArray {
        return runWithProvider {
            toUint8Array(cmac.final()).toByteArray()
        }
    }
}

actual fun CmacSpec.createCmac(secret: SecretKey): Cmac = JsCmac(this, secret)