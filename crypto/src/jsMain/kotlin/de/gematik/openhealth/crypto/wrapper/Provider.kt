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

package de.gematik.openhealth.crypto.wrapper

import de.gematik.openhealth.crypto.LazySuspend
import js.atomic.Atomics
import js.buffer.SharedArrayBuffer
import js.typedarrays.Int32Array
import js.typedarrays.Int8Array
import js.typedarrays.asInt8Array
import kotlinx.atomicfu.AtomicRef
import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.loop
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.await
import kotlinx.coroutines.launch
import kotlinx.coroutines.promise

val Provider = LazySuspend { OpenSslModuleFactory().await() }

fun <T : Any> lazyWithProvider(initializer: OpenSslModule.() -> T) = lazy { initializer(Provider.tryGet()) }

fun <T : Any> runWithProvider(block: OpenSslModule.() -> T): T {
    try {
        return block(Provider.tryGet())
    } catch (error: dynamic) {
        if (js("error instanceof WebAssembly.Exception") == true) {
            throw WebAssemblyException((error.message as Array<String>).joinToString())
        } else {
            throw error as Throwable
        }
    }
}