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

import de.gematik.openhealth.crypto.internal.interop.Uint8Vector
import js.typedarrays.Uint8Array
import js.typedarrays.toUint8Array

/**
 * Converts a Uint8Vector to a ByteArray.
 */
fun Uint8Vector.toByteArray(): ByteArray =
    runWithProvider {
        (toUint8Array(this@toByteArray) as Uint8Array<*>).toByteArray()
    }

/**
 * Converts a ByteArray to a Uint8Vector.
 */
fun ByteArray.toUint8Vector(): Uint8Vector =
    runWithProvider {
        fromUint8Array(this@toUint8Vector.toUint8Array())
    }
