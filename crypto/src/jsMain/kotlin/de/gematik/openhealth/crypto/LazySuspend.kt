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

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Thread-safe implementation of lazy initialization for suspend functions.
 * Provides synchronized access to a lazily initialized value using coroutines.
 */
class LazySuspend<T : Any>(
    private val initializer: suspend () -> T,
) {
    private var value: T? = null
    private var mutex = Mutex()

    /**
     * Gets the lazily initialized value, initializing it if necessary.
     * Uses mutex to ensure thread-safe initialization.
     */
    suspend fun get(): T {
        value?.let { return it }
        return mutex.withLock {
            value ?: initializer().also { value = it }
        }
    }

    /**
     * Gets the value if already initialized.
     * Throws an error if the value hasn't been initialized yet.
     */
    fun tryGet(): T =
        value
            ?: error("Value must be initialized before calling tryGet()")
}
