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

package de.gematik.openhealth.smartcard

import de.gematik.openhealth.smartcard.card.HealthCardScope
import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.exchange.establishTrustedChannel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * Blocking version of [establishTrustedChannel].
 */
@JvmOverloads
fun HealthCardScope.establishTrustedChannelBlocking(
    cardAccessNumber: String,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): TrustedChannelScope =
    runBlocking(dispatcher) {
        establishTrustedChannel(cardAccessNumber)
    }

/**
 * Blocking version of [TrustedChannelScope.transmit].
 */
@JvmOverloads
fun <R> TrustedChannelScope.transmitBlocking(
    exchange: suspend TrustedChannelScope.() -> R,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): R =
    runBlocking(dispatcher) {
        exchange()
    }
