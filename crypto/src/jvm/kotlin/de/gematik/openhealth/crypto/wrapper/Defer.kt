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

import de.gematik.openhealth.crypto.CryptoScope
import de.gematik.openhealth.crypto.internal.interop.ClassHandle

private typealias Deferred = () -> Unit

internal interface DeferScope {
    fun executeAllDeferred()

    fun defer(block: () -> Unit)

    fun <T : Any> T.alsoDefer(): T = also { defer { (it as ClassHandle).jniFreeMemory() } }
}

internal class DeferScopeImpl : DeferScope {
    private var topDeferred: Deferred? = null

    override fun executeAllDeferred() {
        topDeferred?.let {
            it.invoke()
            topDeferred = null
        }
    }

    override fun defer(block: () -> Unit) {
        val currentTop = topDeferred
        topDeferred = {
            try {
                block()
            } finally {
                currentTop?.invoke()
            }
        }
    }
}

internal fun <R> deferScoped(
    allowReturnClassHandle: Boolean = false,
    block: DeferScope.() -> R,
): R {
    val scope = DeferScopeImpl()
    try {
        val value = block(scope)
        if (value != null && !allowReturnClassHandle && value is ClassHandle) {
            error("Native `ClassHandle` returned from `deferScoped`")
        }
        return value
    } finally {
        scope.executeAllDeferred()
    }
}

internal fun <T : Any> DeferScope.lazyDeferred(initializer: () -> T): Lazy<T> =
    lazy {
        initializer().alsoDefer()
    }

internal fun deferred(): DeferScope = DeferScopeImpl()

internal fun deferred(scope: CryptoScope): DeferScope =
    DeferScopeImpl().also {
        scope.defer { it.executeAllDeferred() }
    }
