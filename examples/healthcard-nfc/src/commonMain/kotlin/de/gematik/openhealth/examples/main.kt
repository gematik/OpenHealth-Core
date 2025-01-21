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

package de.gematik.openhealth.examples

import de.gematik.openhealth.crypto.initializeNativeCryptoProvider
import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.card.useHealthCard
import de.gematik.openhealth.smartcard.exchange.establishTrustedChannel
import de.gematik.openhealth.smartcard.exchange.verifyPin
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

expect fun provideSmartCard(): SmartCard

suspend fun main() {
    initializeNativeCryptoProvider()
    provideSmartCard().connect {
        useHealthCard {
            try {
                with(establishTrustedChannel("123123")) {
                    val verifyPinResult = verifyPin("123456")
                    println(verifyPinResult.response.status)
                }
            } catch (err: Exception) {
                println(err.stackTraceToString())
            }
        }
    }
}