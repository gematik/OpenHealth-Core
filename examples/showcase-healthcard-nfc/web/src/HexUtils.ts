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

export function int8ArrayToHex(int8Array: Int8Array) {
  return Array.from(int8Array)
    .map((byte) => (byte & 0xff).toString(16).padStart(2, '0'))
    .join('')
}

export function hexToInt8Array(hexString: string) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hex string length')
  }

  const array = new Int8Array(hexString.length / 2)

  for (let i = 0; i < hexString.length; i += 2) {
    const byte = parseInt(hexString.substring(i, i + 2), 16)
    array[i / 2] = byte > 127 ? byte - 256 : byte // Handle signed values
  }

  return array
}
