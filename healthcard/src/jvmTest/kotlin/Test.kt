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

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.key.EcCurve
import de.gematik.kmp.crypto.key.add
import de.gematik.kmp.crypto.key.toAffine
import de.gematik.kmp.crypto.key.toEcPublicKey
import de.gematik.kmp.crypto.key.toJacobian
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.time.measureTime

private const val TAG_6 = 6
private const val TAG_49 = 0x49

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

class Test {
    @OptIn(ExperimentalCryptoApi::class)
    @Test
    fun asdfs() {
        // test vector according to https://datatracker.ietf.org/doc/html/rfc6932

        val dA =
            BigInteger.parseString(
                "041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699",
                16,
            )
        val x_qA =
            BigInteger.parseString(
                "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
                16,
            )
        val y_qA =
            BigInteger.parseString(
                "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
                16,
            )

        val dB =
            BigInteger.parseString(
                "06F5240EACDB9837BC96D48274C8AA834B6C87BA9CC3EEDD81F99A16B8D804D3",
                16,
            )
        val x_qB =
            BigInteger.parseString(
                "8E07E219BA588916C5B06AA30A2F464C2F2ACFC1610A3BE2FB240B635341F0DB",
                16,
            )
        val y_qB =
            BigInteger.parseString(
                "148EA1D7D1E7E54B9555B6C9AC90629C18B63BEE5D7AA6949EBBF47B24FDE40D",
                16,
            )

        val expected_xZ =
            BigInteger.parseString(
                "05E940915549E9F6A4A75693716E37466ABA79B4BF2919877A16DD2CC2E23708",
                16,
            )
        val expected_yZ =
            BigInteger.parseString(
                "6BC23B6702BC5A019438CEEA107DAAD8B94232FFBBC350F3B137628FE6FD134C",
                16,
            )
        val random: SecureRandom = SecureRandom()

        measureTime {
            val brainpoolParams =
                org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(
                    "brainpoolP256r1",
                )

            val curve = brainpoolParams.curve

            // Party A's public key
            val qA = curve.createPoint(x_qA.toJavaBigInteger(), y_qA.toJavaBigInteger())

            // Party B's public key
            val qB = curve.createPoint(x_qB.toJavaBigInteger(), y_qB.toJavaBigInteger())

            var r = qA
            repeat(1000) {
                r =
                    r.add(
                        curve.createPoint(
                            java.math.BigInteger(128, random),
                            java.math.BigInteger(128, random),
                        ),
                    )
            }

            println(r.getEncoded(false).toList())
        }.let {
            println(it)
        }

        measureTime {
            val curve = EcCurve.BrainpoolP256r1

            // Party A's public key
            val qA = curve.point(x_qA, y_qA).toJacobian()

            // Party B's public key
            val qB = curve.point(x_qB, y_qB).toJacobian()

            var r = qA
            repeat(1000) {
                r = r.add(qB, curve)
            }

            println(r.toAffine(curve).toEcPublicKey())
        }.let {
            println(it)
        }
        measureTime {
            val curve = EcCurve.BrainpoolP256r1

            // Party A's public key
            val qA = curve.point(x_qA, y_qA)

            // Party B's public key
            val qB = curve.point(x_qB, y_qB)

            var r = qA
            repeat(1000) {
                r += qB
            }

            println(r.toEcPublicKey())
        }.let {
            println(it)
        }
    }

    @Test
    fun zdsd() {
        val r =
            DERTaggedObject(
                false,
                BERTags.APPLICATION,
                16384,
                DEROctetString(byteArrayOf(1, 2)),
            ).encoded

        println(r.toHexString())
    }

    private fun createAsn1AuthToken(
        ecPoint: ByteArray,
        protocolID: String,
    ): ByteArray {
        val asn1EncodableVector = ASN1EncodableVector()
        asn1EncodableVector.add(ASN1ObjectIdentifier(protocolID))
        asn1EncodableVector.add(
            DERTaggedObject(
                false,
                TAG_6,
                DEROctetString(ecPoint),
            ),
        )
        return DERTaggedObject(
            false,
            BERTags.APPLICATION,
            TAG_49,
            DERSequence(asn1EncodableVector),
        ).encoded
    }
}