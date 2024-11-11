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

package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EcPointTest {
    private val curve = EcCurve.BrainpoolP256r1

    @Test
    fun `test point at infinity`() =
        runTestWithProvider {
            val point = EcPoint(curve, null, null)
            assertTrue(point.isInfinity)
        }

    @Test
    fun `test regular point`() =
        runTestWithProvider {
            val x =
                BigInteger.parseString(
                    "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
                    16,
                )
            val y =
                BigInteger.parseString(
                    "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
                    16,
                )
            val point = EcPoint(curve, x, y)
            assertFalse(point.isInfinity)
            assertEquals(x, point.x)
            assertEquals(y, point.y)
        }

    @Test
    fun `test invalid point coordinates`() {
        assertFailsWith<IllegalArgumentException> {
            EcPoint(curve, null, BigInteger.ONE)
        }
        assertFailsWith<IllegalArgumentException> {
            EcPoint(curve, BigInteger.ONE, null)
        }
    }

    @Test
    fun `test point negation`() =
        runTestWithProvider {
            val x =
                BigInteger.parseString(
                    "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
                    16,
                )
            val y =
                BigInteger.parseString(
                    "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
                    16,
                )
            val point = EcPoint(curve, x, y)
            val negated = point.negate()

            assertEquals(point.x, negated.x)
            assertEquals((curve.p - point.y!!).mod(curve.p), negated.y)
        }

    @Test
    fun `test uncompressed encoding`() =
        runTestWithProvider {
            val x =
                BigInteger.parseString(
                    "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
                    16,
                )
            val y =
                BigInteger.parseString(
                    "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
                    16,
                )
            val point = EcPoint(curve, x, y)

            val uncompressed = point.uncompressed
            assertEquals(65, uncompressed.size)
            assertEquals(0x04, uncompressed[0])
        }

    @Test
    fun `test uncompressed encoding of point at infinity`() =
        runTestWithProvider {
            val point = EcPoint(curve, null, null)
            assertFailsWith<IllegalArgumentException> {
                point.uncompressed
            }
        }

//    @Test
//    fun `test point addition with infinity`() =
//        runTestWithProvider {
//            val x =
//                BigInteger.parseString(
//                    "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
//                    16,
//                )
//            val y =
//                BigInteger.parseString(
//                    "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
//                    16,
//                )
//            val point = EcPoint(curve, x, y)
//            val infinity = EcPoint(curve, null, null)
//
//            assertFalse(point.isInfinity)
//            assertTrue(infinity.isInfinity)
//
//            val sum1 = point + infinity
//            val sum2 = infinity + point
//            val sum3 = infinity + infinity
//
//            assertEquals(point.x, sum1.x)
//            assertEquals(point.y, sum1.y)
//
//            assertEquals(point.x, sum2.x)
//            assertEquals(point.y, sum2.y)
//
//            assertTrue(sum3.isInfinity)
//        }

    @Test
    fun `test scalar multiplication`() =
        runTestWithProvider {
            val x =
                BigInteger.parseString(
                    "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
                    16,
                )
            val y =
                BigInteger.parseString(
                    "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
                    16,
                )
            val point = EcPoint(curve, x, y)

            val result = point * BigInteger.TWO
            assertFalse(result.isInfinity)
        }

    @Test
    fun `test conversion to EcPublicKey`() =
        runTestWithProvider {
            val x =
                BigInteger.parseString(
                    "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
                    16,
                )
            val y =
                BigInteger.parseString(
                    "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
                    16,
                )
            val point = EcPoint(curve, x, y)

            val publicKey = point.toEcPublicKey()
            assertEquals(curve, publicKey.curve)
            assertEquals(point.uncompressed.toList(), publicKey.data.toList())
        }

    @Test
    fun `test curve coordinate sizes`() =
        runTestWithProvider {
            val x = BigInteger.ONE
            val y = BigInteger.ONE

            val p256Point = EcPoint(EcCurve.BrainpoolP256r1, x, y)
            assertEquals(65, p256Point.uncompressed.size)

            val p384Point = EcPoint(EcCurve.BrainpoolP384r1, x, y)
            assertEquals(97, p384Point.uncompressed.size)

            val p512Point = EcPoint(EcCurve.BrainpoolP512r1, x, y)
            assertEquals(129, p512Point.uncompressed.size)
        }
}
