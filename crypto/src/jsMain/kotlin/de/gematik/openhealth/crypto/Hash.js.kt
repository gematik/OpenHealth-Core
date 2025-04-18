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

import de.gematik.openhealth.crypto.wrapper.DeferScope
import de.gematik.openhealth.crypto.wrapper.deferScoped
import de.gematik.openhealth.crypto.wrapper.deferred
import de.gematik.openhealth.crypto.wrapper.lazyDeferred
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toByteArray
import de.gematik.openhealth.crypto.wrapper.toUint8Vector

/**
 * JavaScript implementation of cryptographic hash functions.
 * Uses the Web Crypto API for hash computations with deferred resource management.
 */
private class JsHash(
    scope: CryptoScope,
    override val spec: HashSpec,
) : Hash,
    DeferScope by deferred(scope) {
    private val hash by lazyDeferred {
        HashGenerator.create(spec.algorithm.name.uppercase())
    }

    /**
     * Updates the hash computation with additional input data.
     */
    override fun update(data: ByteArray) {
        runWithProvider {
            deferScoped { hash.update(data.toUint8Vector().alsoDefer()) }
        }
    }

    /**
     * Completes the hash computation and returns the digest.
     */
    override fun digest(): ByteArray =
        runWithProvider {
            deferScoped { hash.final().alsoDefer().toByteArray() }
        }
}

/**
 * JavaScript-specific implementation for creating hash instances.
 * Creates a new hash instance using the Web Crypto API.
 */
actual fun HashSpec.nativeCreateHash(scope: CryptoScope): Hash = JsHash(scope, this)
