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

import de.gematik.openhealth.crypto.cipher.AesCipher
import de.gematik.openhealth.crypto.cipher.AesCipherSpec
import de.gematik.openhealth.crypto.cipher.AesDecipher
import de.gematik.openhealth.crypto.cipher.AesDecipherSpec
import de.gematik.openhealth.crypto.cipher.nativeCreateCipher
import de.gematik.openhealth.crypto.cipher.nativeCreateDecipher
import de.gematik.openhealth.crypto.exchange.Ecdh
import de.gematik.openhealth.crypto.exchange.EcdhSpec
import de.gematik.openhealth.crypto.exchange.nativeCreateKeyExchange
import de.gematik.openhealth.crypto.kem.KemDecapsulation
import de.gematik.openhealth.crypto.kem.KemEncapsulation
import de.gematik.openhealth.crypto.kem.KemSpec
import de.gematik.openhealth.crypto.kem.nativeCreateDecapsulation
import de.gematik.openhealth.crypto.kem.nativeCreateEncapsulation
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.SecretKey

/**
 * Defines a scope for cryptographic operations that manage resources requiring explicit release or
 * closure.
 */
@ExperimentalCryptoApi
abstract class CryptoScope {
    /**
     * Releases any resources associated with this scope.
     */
    internal abstract fun release()

    internal abstract fun defer(block: () -> Unit)

    /**
     * Creates a Cipher-Based Message Authentication Code instance with the specified [secret].
     */
    fun CmacSpec.createCmac(secret: SecretKey): Cmac = nativeCreateCmac(this@CryptoScope, secret)

    fun HashSpec.createHash(): Hash = nativeCreateHash(this@CryptoScope)

    /**
     * Creates an Elliptic-curve Diffie–Hellman key agreement instance with the
     * specified [privateKey].
     */
    fun EcdhSpec.createKeyExchange(privateKey: EcPrivateKey): Ecdh =
        nativeCreateKeyExchange(this@CryptoScope, privateKey)

    /**
     * Creates a Key Encapsulation instance with the specified [privateKey].
     */
    fun KemSpec.createEncapsulation(encapsulationKey: ByteArray): KemEncapsulation =
        nativeCreateEncapsulation(this@CryptoScope, encapsulationKey)

    fun KemSpec.createDecapsulation(): KemDecapsulation =
        nativeCreateDecapsulation(this@CryptoScope)

    fun AesCipherSpec.createCipher(key: SecretKey): AesCipher =
        nativeCreateCipher(this@CryptoScope, key)

    fun AesDecipherSpec.createDecipher(key: SecretKey): AesDecipher =
        nativeCreateDecipher(this@CryptoScope, key)
}

/**
 * Executes the specified [block] of cryptographic operations within a managed [CryptoScope],
 * ensuring that all resources are properly closed or released afterward.
 *
 * Returning objects created by or inheriting from [CryptoScope] is disallowed.
 */
@ExperimentalCryptoApi
fun <R : Any?> useCrypto(block: CryptoScope.() -> R): R = nativeUseCrypto(block)

suspend fun <R : Any?> useCryptoAsync(block: suspend CryptoScope.() -> R): R =
    nativeUseCrypto(block)

internal expect fun <R : Any?> nativeUseCrypto(block: CryptoScope.() -> R): R

internal expect suspend fun <R : Any?> nativeUseCrypto(block: suspend CryptoScope.() -> R): R