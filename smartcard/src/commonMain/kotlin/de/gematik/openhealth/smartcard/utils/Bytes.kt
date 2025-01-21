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

package de.gematik.openhealth.smartcard.utils

private const val PAD = 0x80.toByte()

/**
 * Padding the data with [paddingByte].
 */
fun padData(
    data: ByteArray,
    blockSize: Int,
    paddingByte: Byte = PAD
): ByteArray =
    ByteArray(data.size + (blockSize - data.size % blockSize)).apply {
        data.copyInto(this)
        this[data.size] = paddingByte
    }

/**
 * Removes the padding from [paddedData].
 */
fun unpadData(paddedData: ByteArray, paddingByte: Byte = PAD): ByteArray {
    for (i in paddedData.indices.reversed()) {
        if (paddedData[i] == paddingByte) {
            return paddedData.copyOfRange(0, i)
        }
    }
    return paddedData
}