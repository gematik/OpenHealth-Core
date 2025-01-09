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

import de.gematik.openhealth.crypto.wrapper.lazyWithProvider
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import js.typedarrays.toUint8Array

private class JsHash(
    override val spec: HashSpec,
) : Hash {
    private val hash by lazyWithProvider {
        HashGenerator.create(spec.algorithm.name);
    }

    override fun update(data: ByteArray) {
        runWithProvider {
            hash.update(fromUint8Array(data.toUint8Array()))
        }
    }

    override  fun digest(): ByteArray {
        return runWithProvider {
            toUint8Array(hash.final()).toByteArray()
        }
    }
}

actual fun HashSpec.createHash(): Hash = JsHash(this)