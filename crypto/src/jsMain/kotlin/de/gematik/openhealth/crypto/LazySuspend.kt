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

import de.gematik.openhealth.crypto.wrapper.WebAssemblyException
import de.gematik.openhealth.crypto.wrapper.OpenSslModule
import de.gematik.openhealth.crypto.wrapper.Provider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class LazySuspend<T : Any>(private val initializer: suspend () -> T) {
    private var value: T? = null
    private var mutex = Mutex()

    suspend fun get(): T {
        value?.let { return it }
        return mutex.withLock {
            value ?: initializer().also { value = it }
        }
    }

    fun tryGet(): T {
        return value ?: throw IllegalStateException("Value must be initialized before calling tryGet()")
    }
}
