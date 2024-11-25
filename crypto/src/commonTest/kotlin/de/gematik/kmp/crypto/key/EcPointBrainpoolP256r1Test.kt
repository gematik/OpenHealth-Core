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

package de.gematik.kmp.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.kmp.crypto.UnoptimizedCryptoApi
import kotlin.test.Test
import kotlin.test.assertEquals

@OptIn(UnoptimizedCryptoApi::class)
@Suppress("ktlint:standard:max-line-length")
class EcPointBrainpoolP256r1Test {
    private val curve = EcCurve.BrainpoolP256r1

    @Test
    fun `test vector - rfc6932`() {
        // test vector according to https://datatracker.ietf.org/doc/html/rfc6932

        val dA = BigInteger.parseString("041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699",16)
        val x_qA = BigInteger.parseString("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",16)
        val y_qA = BigInteger.parseString("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",16)

        val dB = BigInteger.parseString("06F5240EACDB9837BC96D48274C8AA834B6C87BA9CC3EEDD81F99A16B8D804D3",16)
        val x_qB = BigInteger.parseString("8E07E219BA588916C5B06AA30A2F464C2F2ACFC1610A3BE2FB240B635341F0DB",16)
        val y_qB = BigInteger.parseString("148EA1D7D1E7E54B9555B6C9AC90629C18B63BEE5D7AA6949EBBF47B24FDE40D",16)

        val expected_xZ = BigInteger.parseString("05E940915549E9F6A4A75693716E37466ABA79B4BF2919877A16DD2CC2E23708",16)
        val expected_yZ = BigInteger.parseString("6BC23B6702BC5A019438CEEA107DAAD8B94232FFBBC350F3B137628FE6FD134C",16)

        // Party A's public key
        val qA = curve.point(x_qA, y_qA)

        // Party B's public key
        val qB = curve.point(x_qB, y_qB)

        // Compute shared secret (A's perspective)
        val sharedSecretA = qB * dA

        // Compute shared secret (B's perspective)
        val sharedSecretB = qA * dB

        // Verify
        assertEquals(expected_xZ, sharedSecretA.x)
        assertEquals(expected_yZ, sharedSecretA.y)
        assertEquals(expected_xZ, sharedSecretB.x)
        assertEquals(expected_yZ, sharedSecretB.y)
        assertEquals(sharedSecretA, sharedSecretB)
    }

    @Test
    fun `add two points`() {
        val point1 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val point2 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("743CF1B8B5CD4F2EB55F8AA369593AC436EF044166699E37D51A14C2CE13EA0E", 16), BigInteger.parseString("36ED163337DEBA9C946FE0BB776529DA38DF059F69249406892ADA097EEB7CD4", 16))
        assertEquals(expected, point1 + point2)
    }

    @Test
    fun `add infinity to a point`() {
        val point1 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val point2 = curve.point(null, null)
        val expected = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        assertEquals(expected, point1 + point2)
    }

    @Test
    fun `add point to its negation`() {
        val point1 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val point2 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("-547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(null, null)
        assertEquals(expected, point1 + point2)
    }

    @Test
    fun `double a point`() {
        val point1 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("743CF1B8B5CD4F2EB55F8AA369593AC436EF044166699E37D51A14C2CE13EA0E", 16), BigInteger.parseString("36ED163337DEBA9C946FE0BB776529DA38DF059F69249406892ADA097EEB7CD4", 16))
        assertEquals(expected, point1.double())
    }

    @Test
    fun `scalar multiplication by 0`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(null, null)
        val result = point * BigInteger.parseString("0", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 1`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val result = point * BigInteger.parseString("1", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 2`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("743CF1B8B5CD4F2EB55F8AA369593AC436EF044166699E37D51A14C2CE13EA0E", 16), BigInteger.parseString("36ED163337DEBA9C946FE0BB776529DA38DF059F69249406892ADA097EEB7CD4", 16))
        val result = point * BigInteger.parseString("2", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 3`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("A8F217B77338F1D4D6624C3AB4F6CC16D2AA843D0C0FCA016B91E2AD25CAE39D", 16), BigInteger.parseString("4B49CAFC7DAC26BB0AA2A6850A1B40F5FAC10E4589348FB77E65CC5602B74F9D", 16))
        val result = point * BigInteger.parseString("3", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 4`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("3672030BACE787AA319E21D40645B2999006BEEC437FD084DD3FC592F5FCD77C", 16), BigInteger.parseString("335B226CE5FAC0C36A18CE42E95F43C9EED3E256BDD0C98E55A069595515D15B", 16))
        val result = point * BigInteger.parseString("4", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 5`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("855433A3A4C8E334A5F863E8B69FC1477CF41589C0D8C3FB32F95F7C85FE101D", 16), BigInteger.parseString("A50C95EFC2AD06C4D7E172E40350D911097082129591C88BEF9E224A5FD8814C", 16))
        val result = point * BigInteger.parseString("5", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 6`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("78EA164AA2A74A67A04B680BD8BB1384E7CC4DB8774C50ECB9DFB344771026B1", 16), BigInteger.parseString("10D988FF681802469B49D341F8DA0A2500CAD34F1E745B1437E336573D08B1BE", 16))
        val result = point * BigInteger.parseString("6", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 7`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("6B8BB7F53E36B6824D3300AFBC27257BD432568E24E5FB5702295ECD04E9DE4C", 16), BigInteger.parseString("382F9AF51CE9A3D30965A09661223AF5646067C55B1A928F7252376BFC79EBF0", 16))
        val result = point * BigInteger.parseString("7", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 8`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("545A6FAF6B031B267409483A38D1942C91DB2B4EB917D2BDDA994B4CB3985461", 16), BigInteger.parseString("76F4942D7CA7B4143CBEDFC72C7A65194596BDA3D83213BBCFB32792456303FC", 16))
        val result = point * BigInteger.parseString("8", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 9`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("8B5FA06D31D59D690811364099019B7CD283BD714A67C06A420D27D6784F8F12", 16), BigInteger.parseString("41E0E0C34464B5C7AE64ED13D26D038E146F15EEA266B22842BE764F293B3348", 16))
        val result = point * BigInteger.parseString("9", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 10`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("A4348DB079F7FFBCFB3DFC35BD8AC67C22A85A50025CB1F37A22BA81728B1CAF", 16), BigInteger.parseString("2444FA0F5B79BE1A2BD1D073C38FD136C77977F417B550D954E46DC4C8B737C1", 16))
        val result = point * BigInteger.parseString("A", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 100`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("9A8755EAC4FD597412605ED57C5130463EA74444843CCE26DE6C131827A0EBF", 16), BigInteger.parseString("7FBA8949F72FD5ABA616C78EAC619FC11099EABE1AC89F5F6225A293A3916F72", 16))
        val result = point * BigInteger.parseString("64", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 1000`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("6AC06C5ACA4CEBB8C01FDDEF758D53EA3AC2FCD5ED97D81EDCD7E38C8914434A", 16), BigInteger.parseString("416B4BBD1CC4BC5EA1B7E97012DF1181CAED64F0ED798A7BA1BA72A6D50F3C", 16))
        val result = point * BigInteger.parseString("3E8", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication by 10000`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("A8F6B1E51E6F1284B681D5160D9260B622D83675231BA402F32BBE227A0C64C0", 16), BigInteger.parseString("501306E6A31703C6EDD93CF93115CBDC3D63F814CB140D5CF8307DED3C598C5D", 16))
        val result = point * BigInteger.parseString("2710", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication with edge scalar 76884956397045344220809746629001649092737531784414529538755519063063536359078`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("557C5FA5DE13E4BEA66DC47689226FA8ABC4B110A73891D3C3F5F355F069E9E0", 16))
        val result = point * BigInteger.parseString("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A6", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication with edge scalar 76884956397045344220809746629001649092737531784414529538755519063063536359079`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(null, null)
        val result = point * BigInteger.parseString("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `scalar multiplication with edge scalar 76884956397045344220809746629001649092737531784414529538755519063063536359080`() {
        val point = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val result = point * BigInteger.parseString("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A8", 16)
        assertEquals(expected, result)
    }

    @Test
    fun `random point addition 1`() {
        val point1 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val point2 = curve.point(BigInteger.parseString("743CF1B8B5CD4F2EB55F8AA369593AC436EF044166699E37D51A14C2CE13EA0E", 16), BigInteger.parseString("36ED163337DEBA9C946FE0BB776529DA38DF059F69249406892ADA097EEB7CD4", 16))
        val expected = curve.point(BigInteger.parseString("A8F217B77338F1D4D6624C3AB4F6CC16D2AA843D0C0FCA016B91E2AD25CAE39D", 16), BigInteger.parseString("4B49CAFC7DAC26BB0AA2A6850A1B40F5FAC10E4589348FB77E65CC5602B74F9D", 16))
        assertEquals(expected, point1 + point2)
    }

    @Test
    fun `random point addition 2`() {
        val point1 = curve.point(BigInteger.parseString("A8F217B77338F1D4D6624C3AB4F6CC16D2AA843D0C0FCA016B91E2AD25CAE39D", 16), BigInteger.parseString("4B49CAFC7DAC26BB0AA2A6850A1B40F5FAC10E4589348FB77E65CC5602B74F9D", 16))
        val point2 = curve.point(BigInteger.parseString("3672030BACE787AA319E21D40645B2999006BEEC437FD084DD3FC592F5FCD77C", 16), BigInteger.parseString("335B226CE5FAC0C36A18CE42E95F43C9EED3E256BDD0C98E55A069595515D15B", 16))
        val expected = curve.point(BigInteger.parseString("6B8BB7F53E36B6824D3300AFBC27257BD432568E24E5FB5702295ECD04E9DE4C", 16), BigInteger.parseString("382F9AF51CE9A3D30965A09661223AF5646067C55B1A928F7252376BFC79EBF0", 16))
        assertEquals(expected, point1 + point2)
    }

    @Test
    fun `negate a point`() {
        val point1 = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16))
        val expected = curve.point(BigInteger.parseString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16), BigInteger.parseString("557C5FA5DE13E4BEA66DC47689226FA8ABC4B110A73891D3C3F5F355F069E9E0", 16))
        assertEquals(expected, point1.negate())
    }
}