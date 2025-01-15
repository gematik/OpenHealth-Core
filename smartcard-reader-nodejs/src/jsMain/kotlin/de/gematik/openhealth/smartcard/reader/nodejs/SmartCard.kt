/*
 * Copyright (c) 2024 gematik GmbH
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

package de.gematik.openhealth.smartcard.reader.nodejs

import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.single
import kotlinx.coroutines.suspendCancellableCoroutine
import node.buffer.Buffer
import kotlin.coroutines.resume

private const val MAX_APDU_LENGTH = 65536 // extended length in bytes

class NodeSmartCardException(
    error: Any?,
) : Exception(error?.toString())

private class NodeSmartCard : SmartCard() {
    class NodeCommunicationScope(
        internal val reader: CardReader,
        private val protocol: Int,
    ) : CommunicationScope {
        override val cardIdentifier: String = reader.name
        override val supportsExtendedLength: Boolean = true

        override suspend fun transmit(apdu: CardCommandApdu): CardResponseApdu {
            val commandBuffer = Buffer.from(apdu.bytes)
            val responseBuffer =
                suspendCancellableCoroutine { continuation ->
                    reader.transmit(commandBuffer, MAX_APDU_LENGTH, protocol) { err, response ->
                        if (err != null) {
                            continuation.cancel(NodeSmartCardException(err))
                        } else {
                            continuation.resume(response)
                        }
                    }
                }
            return CardResponseApdu(responseBuffer.toByteArray())
        }
    }

    override suspend fun <T> connect(block: suspend CommunicationScope.() -> T): T =
        callbackFlow {
            val pcsc = pcsc()

            pcsc.on("reader") { reader: CardReader ->
                reader.on("error") { err ->
                    cancel(err.toString())
                }

                reader.on("status") { status: Status ->
                    // Check what has changed
                    val changes = reader.state xor status.state
                    if (changes != 0) {
                        when {
                            (changes and reader.SCARD_STATE_EMPTY != 0) &&
                                (status.state and reader.SCARD_STATE_EMPTY != 0) -> {
                                // card removed
                                reader.disconnect(reader.SCARD_LEAVE_CARD) { err ->
                                    if (err != null) {
                                        cancel(err.toString())
                                    }
                                }
                            }

                            (changes and reader.SCARD_STATE_PRESENT != 0) &&
                                (status.state and reader.SCARD_STATE_PRESENT != 0) -> {
                                // card inserted
                                reader.connect(
                                    object : ConnectOptions {
                                        override var share_mode: Int? = reader.SCARD_SHARE_SHARED
                                        override var protocol: Int? = null
                                    },
                                ) { err, protocol ->
                                    if (err != null) {
                                        cancel(err.toString())
                                    } else {
                                        trySend(NodeCommunicationScope(reader, protocol))
                                    }
                                }
                            }
                        }
                    }
                }

                @Suppress("USELESS_CAST")
                reader.on(
                    "end",
                    {
                        cancel("PCSC communication ended")
                    } as () -> Unit,
                ) // requires cast
            }

            pcsc.on("error") { err ->
                cancel(err.toString())
            }

            awaitClose {
                pcsc.close()
            }
        }.map { scope ->
            block(scope).also { scope.reader.close() }
        }.single()
}

@JsExport
fun createPcscSmartCard(): SmartCard = NodeSmartCard()