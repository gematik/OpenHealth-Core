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

package abc

import node.buffer.Buffer
import node.events.EventEmitter

external interface ConnectOptions {
    var share_mode: Int?
    var protocol: Int?
}

external interface Status {
    var atr: Buffer?
    var state: Int
}

external class PCSCLite : EventEmitter {
    fun on(type: String /* "error" */, listener: (error: Any) -> Unit): PCSCLite

    fun once(type: String /* "error" */, listener: (error: Any) -> Unit): PCSCLite

    fun on(type: String /* "reader" */, listener: (reader: CardReader) -> Unit): PCSCLite

    fun once(type: String /* "reader" */, listener: (reader: CardReader) -> Unit): PCSCLite

    fun close()
}

external class CardReader : EventEmitter {
    val SCARD_SHARE_SHARED: Int
    val SCARD_SHARE_EXCLUSIVE: Int
    val SCARD_SHARE_DIRECT: Int

    val SCARD_PROTOCOL_T0: Int
    val SCARD_PROTOCOL_T1: Int
    val SCARD_PROTOCOL_RAW: Int

    val SCARD_STATE_UNAWARE: Int
    val SCARD_STATE_IGNORE: Int
    val SCARD_STATE_CHANGED: Int
    val SCARD_STATE_UNKNOWN: Int
    val SCARD_STATE_UNAVAILABLE: Int
    val SCARD_STATE_EMPTY: Int
    val SCARD_STATE_PRESENT: Int
    val SCARD_STATE_ATRMATCH: Int
    val SCARD_STATE_EXCLUSIVE: Int
    val SCARD_STATE_INUSE: Int
    val SCARD_STATE_MUTE: Int

    val SCARD_LEAVE_CARD: Int
    val SCARD_RESET_CARD: Int
    val SCARD_UNPOWER_CARD: Int
    val SCARD_EJECT_CARD: Int

    val name: String
    val state: Int
    val connected: Boolean

    fun on(type: String /* "error" */, listener: (error: Any) -> Unit): CardReader

    fun once(type: String /* "error" */, listener: (error: Any) -> Unit): CardReader

    fun on(type: String /* "end" */, listener: () -> Unit): CardReader

    fun once(type: String /* "end" */, listener: () -> Unit): CardReader

    fun on(type: String /* "status" */, listener: (status: Status) -> Unit): CardReader

    fun once(type: String /* "status" */, listener: (status: Status) -> Unit): CardReader

    fun SCARD_CTL_CODE(code: Int): Int

    fun get_status(cb: (err: Any?, state: Int, atr: Buffer?) -> Unit)

    fun connect(callback: (err: Any?, protocol: Int) -> Unit)

    fun connect(
        options: ConnectOptions,
        callback: (err: Any?, protocol: Int) -> Unit,
    )

    fun disconnect(callback: (err: Any?) -> Unit)

    fun disconnect(
        disposition: Int,
        callback: (err: Any?) -> Unit,
    )

    fun transmit(
        data: Buffer,
        res_len: Int,
        protocol: Int,
        cb: (err: Any?, response: Buffer) -> Unit,
    )

    fun control(
        data: Buffer,
        control_code: Int,
        res_len: Int,
        cb: (err: Any?, response: Buffer) -> Unit,
    )

    fun close()
}

@JsModule("pcsclite")
@JsNonModule
@JsName("default")
external fun pcsc(): PCSCLite