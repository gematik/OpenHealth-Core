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
import de.gematik.openhealth.crypto.internal.interop.CryptoModule

private typealias Deferred = () -> Unit

/**
 * Interface for managing deferred operations in a scope.
 */
internal interface DeferScope {
    fun executeAllDeferred()

    fun defer(block: () -> Unit)

    fun <T : ClassHandle> T.alsoDefer(): T = also { defer { delete() } }
}

/**
 * Implementation of DeferScope that maintains a chain of deferred operations.
 * Operations are executed in reverse order of registration (last-in-first-out).
 */
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

private fun Any.isClassHandle(): Boolean {
    val v = this.asDynamic()
    return v.isAliasOf != undefined &&
        v.delete != undefined &&
        v.deleteLater != undefined &&
        v.isDeleted != undefined &&
        v.clone != undefined
}

/**
 * Executes a block within a deferred scope and handles cleanup of resources.
 */
internal fun <R> deferScoped(
    allowReturnClassHandle: Boolean = false,
    block: DeferScope.() -> R,
): R {
    val scope = DeferScopeImpl()
    try {
        val value = block(scope)
        if (value != null && !allowReturnClassHandle && value.isClassHandle()) {
            error("Native `ClassHandle` returned from `deferScoped`")
        }
        return value
    } finally {
        scope.executeAllDeferred()
    }
}

/**
 * Creates a lazy-initialized deferred value from a native module initializer.
 */
internal fun <T : ClassHandle> DeferScope.lazyDeferred(
    initializer: CryptoModule.() -> T,
): Lazy<T> =
    lazy {
        initializer(Provider.tryGet()).alsoDefer()
    }

/**
 * Creates a new deferred scope.
 */
internal fun deferred(): DeferScope = DeferScopeImpl()

/**
 * Creates a new deferred scope linked to a crypto scope.
 */
internal fun deferred(scope: CryptoScope): DeferScope =
    DeferScopeImpl().also {
        scope.defer { it.executeAllDeferred() }
    }
