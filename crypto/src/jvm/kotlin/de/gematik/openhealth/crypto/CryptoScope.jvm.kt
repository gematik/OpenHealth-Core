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

/**
 * JVM implementation of the CryptoScope.
 * Handles resource management and deferred execution of cryptographic operations.
 */
internal class JvmCryptoScope : CryptoScope() {
    override fun release() {
        // noop
    }

    override fun defer(block: () -> Unit) {
        // noop
    }
}

/**
 * JVM-specific implementation for synchronous cryptographic operations.
 * Executes the given block within a crypto scope.
 */
internal actual fun <R : Any?> nativeUseCrypto(block: CryptoScope.() -> R): R =
    block(JvmCryptoScope())

/**
 * JVM-specific implementation for asynchronous cryptographic operations.
 * Executes the given suspend block within a crypto scope.
 */
internal actual suspend fun <R : Any?> nativeUseCryptSuspendable(block: suspend CryptoScope.() -> R): R =
    block(JvmCryptoScope())
