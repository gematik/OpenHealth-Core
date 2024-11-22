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
import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.jce.ECNamedCurveTable
import kotlin.test.Test


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
//        val ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolP256r1")
//
//
//        // Define two points on the curve using their coordinates
//        val point1 = ecSpec.getCurve().createPoint(
//            BigInteger("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16),
//            BigInteger("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16)
//        )
//
//        val r = point1.multiply(BigInteger("-20", 10)).normalize()
//
//        println(r.getAffineXCoord().toBigInteger())
//        println(r.getAffineYCoord().toBigInteger())
//
//        val point = EcCurve.BrainpoolP256r1.point(com.ionspin.kotlin.bignum.integer.BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), com.ionspin.kotlin.bignum.integer.BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
//        val result = point.multiply(com.ionspin.kotlin.bignum.integer.BigInteger.parseString("-20", 10))
//        println(result.x?.toJavaBigInteger())
//        println(result.y?.toJavaBigInteger())

        val dA = BigInteger.parseString("041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699",16)
        val x_qA = BigInteger.parseString("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",16)
        val y_qA = BigInteger.parseString("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",16)

        val dB = BigInteger.parseString("06F5240EACDB9837BC96D48274C8AA834B6C87BA9CC3EEDD81F99A16B8D804D3",16)
        val x_qB = BigInteger.parseString("8E07E219BA588916C5B06AA30A2F464C2F2ACFC1610A3BE2FB240B635341F0DB",16)
        val y_qB = BigInteger.parseString("148EA1D7D1E7E54B9555B6C9AC90629C18B63BEE5D7AA6949EBBF47B24FDE40D",16)

        val expected_xZ = BigInteger.parseString("05E940915549E9F6A4A75693716E37466ABA79B4BF2919877A16DD2CC2E23708",16)
        val expected_yZ = BigInteger.parseString("6BC23B6702BC5A019438CEEA107DAAD8B94232FFBBC350F3B137628FE6FD134C",16)

        val curve = EcCurve.BrainpoolP256r1

        // Party A's public key
        val qA = curve.point(x_qA, y_qA)

        // Party B's public key
        val qB = curve.point(x_qB, y_qB)

        // Compute shared secret (A's perspective)
        val sharedSecretA = qB.multiply(dA)

        // Compute shared secret (B's perspective)
        val sharedSecretB = qA.multiply(dB)

        println("Shared Secret (A): x=${sharedSecretA.x}, y=${sharedSecretA.y}")
        println("Shared Secret (B): x=${sharedSecretB.x}, y=${sharedSecretB.y}")

        // Verify
        require(sharedSecretA.x == expected_xZ && sharedSecretA.y == expected_yZ) { "Shared secret A doesn't match expected" }
        require(sharedSecretB.x == expected_xZ && sharedSecretB.y == expected_yZ) { "Shared secret B doesn't match expected" }
        require(sharedSecretA == sharedSecretB) { "Shared secrets do not match between parties" }

        println("ECDH Test Passed!")


    }

    @Test
    fun zdsd() {
        val r = DERTaggedObject(
            true,
            BERTags.APPLICATION,
            28,
            DERTaggedObject(false, 1, DEROctetString(byteArrayOf(1,2)))
        ).encoded

        println(r.toHexString())
    }
}