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

package de.gematik.openhealth.crypto.wrapper

import de.gematik.openhealth.crypto.LazySuspend
import de.gematik.openhealth.crypto.internal.interop.CryptoModule
import de.gematik.openhealth.crypto.internal.interop.CryptoModuleFactory
import kotlinx.coroutines.await

/**
 * Lazy provider for the OpenSSL module instance.
 */
val Provider = LazySuspend { CryptoModuleFactory().await() }

/**
 * Executes a block with the OpenSSL module provider, handling WebAssembly exceptions.
 */
@Suppress("detekt.SwallowedException", "detekt.InstanceOfCheckForException")
fun <T : Any> runWithProvider(block: CryptoModule.() -> T): T =
    try {
        block(Provider.tryGet())
    } catch (error: dynamic) {
        if (js("error instanceof WebAssembly.Exception") == true) {
            throw WebAssemblyException((error.message as Array<String>).joinToString())
        } else {
            throw error as Throwable
        }
    }
