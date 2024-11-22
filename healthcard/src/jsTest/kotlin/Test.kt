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

import abc.CardReader
import abc.ConnectOptions
import abc.Status
import abc.pcsc
import de.gematik.kmp.healthcard.model.card.ICardChannel
import de.gematik.kmp.healthcard.model.card.IHealthCard
import de.gematik.kmp.healthcard.model.command.CommandApdu
import de.gematik.kmp.healthcard.model.command.ResponseApdu
import de.gematik.kmp.healthcard.model.exchange.establishTrustedChannel
import js.coroutines.promise
import js.promise.catch
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.test.runTest
import node.buffer.Buffer
import kotlin.coroutines.resume
import kotlin.test.Test

class CardChannel(private val reader: CardReader) : ICardChannel {
    override val card: IHealthCard
        get() = object : IHealthCard {
            override fun transmit(apduCommand: CommandApdu): ResponseApdu {
                TODO("Not yet implemented")
            }
        }

    override val maxTransceiveLength: Int
        get() = 65536 // Extended APDU max length

    override val isExtendedLengthSupported: Boolean
        get() = true

    override suspend fun transmit(command: CommandApdu): ResponseApdu {
        println("Transmit apdu 1")
        val protocol = reader.SCARD_PROTOCOL_T1
        val commandBuffer = Buffer.from(command.bytes)
        val responseLength = maxTransceiveLength
        val responseBuffer = suspendCancellableCoroutine { continuation ->
            reader.transmit(commandBuffer, responseLength, protocol) { err, response ->
                println("Transmit apdu")
                if (err != null) {
                    println(err)
                    continuation.cancel(Throwable(err.toString()))
                } else {
                    continuation.resume(response)
                }
            }
        }
        return ResponseApdu(responseBuffer.toByteArray())
    }
}

class Test {

    @Test
    fun saddssdfsf() = runTest {
        val pcsc = pcsc()

        val reader = suspendCancellableCoroutine { continuation ->
            pcsc.on("reader") { reader: CardReader ->
                println("New reader detected: ${reader.name}")

                reader.on("error") { err ->
                    println("Error(${reader.name}): ${err}")
                }

                reader.on("status") { status: Status ->
                    println("Status(${reader.name}): $status")

                    // Check what has changed
                    val changes = reader.state xor status.state
                    if (changes != 0) {
                        if ((changes and reader.SCARD_STATE_EMPTY != 0) && (status.state and reader.SCARD_STATE_EMPTY != 0)) {
                            println("Card removed")
                            reader.disconnect(reader.SCARD_LEAVE_CARD) { err ->
                                if (err != null) {
                                    println(err)
                                } else {
                                    println("Disconnected")
                                }
                            }
                        } else if ((changes and reader.SCARD_STATE_PRESENT != 0) && (status.state and reader.SCARD_STATE_PRESENT != 0)) {
                            println("Card inserted")
                            reader.connect(object : ConnectOptions {
                                override var share_mode: Int? = reader.SCARD_SHARE_SHARED
                                override var protocol: Int? = null
                            }) { err, protocol ->
                                if (err != null) {
                                    println(err)
                                } else {
//                                println("Protocol(${reader.name}): $protocol")
//                                val command = js("Buffer.from([0x00, 0xB0, 0x00, 0x00, 0x20])")
//                                reader.transmit(command, 40, protocol) { transmitErr, data ->
//                                    if (transmitErr != null) {
//                                        println(transmitErr)
//                                    } else {
//                                        println("Data received: $data")
//                                        reader.close()
//                                        pcsc.close()
//                                    }
//                                }

                                    continuation.resume(reader)
                                }
                            }
                        }
                    }
                }

                reader.on("end") { _ ->
                    println("Reader ${reader.name} removed")
                }
            }

            pcsc.on("error") { err ->
                println("PCSC error: ${err}")
            }
        }

        println("establishTrustedChannel")
        CardChannel(reader).establishTrustedChannel("123123")

        reader.close()
        pcsc.close()
    }
}