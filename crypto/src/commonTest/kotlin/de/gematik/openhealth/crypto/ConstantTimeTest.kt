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

package de.gematik.openhealth.crypto

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConstantTimeTest {
    @Test
    fun `equal arrays should return true`() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(1, 2, 3, 4, 5)

        assertTrue(array1.contentConstantTimeEquals(array2))
    }

    @Test
    fun `different arrays should return false`() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(1, 2, 3, 4, 6)

        assertFalse(array1.contentConstantTimeEquals(array2))
    }

    @Test
    fun `arrays of different length should return false`() {
        val array1 = byteArrayOf(1, 2, 3, 4, 5)
        val array2 = byteArrayOf(1, 2, 3, 4)

        assertFalse(array1.contentConstantTimeEquals(array2))
    }

    @Test
    fun `empty arrays should return true`() {
        val array1 = byteArrayOf()
        val array2 = byteArrayOf()

        assertTrue(array1.contentConstantTimeEquals(array2))
    }

    @Test
    fun `same array reference should return true`() {
        val array = byteArrayOf(1, 2, 3)

        assertTrue(array.contentConstantTimeEquals(array))
    }
}
