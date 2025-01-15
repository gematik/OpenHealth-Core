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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.TestResult
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

class TestProviderScope(
    val testScope: TestScope,
    val cryptoScope: CryptoScope,
) : CryptoScope(),
    CoroutineScope by testScope {
    override fun release() {
        cryptoScope.release()
    }

    override fun defer(block: () -> Unit) {
        cryptoScope.defer(block)
    }
}

fun runTestWithProvider(
    context: CoroutineContext = EmptyCoroutineContext,
    testBody: suspend TestProviderScope.() -> Unit,
): TestResult =
    runTest(
        context = context,
    ) {
        useCryptoAsync {
            initializeNativeProvider()
            testBody(TestProviderScope(this@runTest, this@useCryptoAsync))
        }
    }