package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals

@Suppress("ktlint:standard:max-line-length")
class EcPointBrainpoolP384r1Test {
    private val curve = EcCurve.BrainpoolP384r1

    @Test
    fun `test vector - rfc6932`() =
        runTestWithProvider {
            // Test vector according to https://datatracker.ietf.org/doc/html/rfc6932

            val dA =
                BigInteger.parseString(
                    "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
                    16,
                )
            val xQa =
                BigInteger.parseString(
                    "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068",
                    16,
                )
            val yQa =
                BigInteger.parseString(
                    "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
                    16,
                )

            val dB =
                BigInteger.parseString(
                    "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670",
                    16,
                )
            val xQb =
                BigInteger.parseString(
                    "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4",
                    16,
                )
            val yQb =
                BigInteger.parseString(
                    "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
                    16,
                )

            val expectedXZ =
                BigInteger.parseString(
                    "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42",
                    16,
                )
            val expectedYZ =
                BigInteger.parseString(
                    "DF213417EBE4D8E40A5F76F66C56470C489A3478D146DECF6DF0D94BAE9E598157290F8756066975F1DB34B2324B7BD",
                    16,
                )

            val qA = curve.point(xQa, yQa)
            val qB = curve.point(xQb, yQb)

            println("qA: x=${qA.x?.toString(16)}, y=${qA.y?.toString(16)}")
            println("qB: x=${qB.x?.toString(16)}, y=${qB.y?.toString(16)}")

            val sharedSecretA = qB * dA
            val sharedSecretB = qA * dB

            println(
                "sharedSecretA: x=${sharedSecretA.x?.toString(
                    16,
                )}, y=${sharedSecretA.y?.toString(16)}",
            )
            println(
                "sharedSecretB: x=${sharedSecretB.x?.toString(
                    16,
                )}, y=${sharedSecretB.y?.toString(16)}",
            )
            println("expected: x=${expectedXZ.toString(16)}, y=${expectedYZ.toString(16)}")

            assertEquals(expectedXZ, sharedSecretA.x)
            assertEquals(expectedYZ, sharedSecretA.y)
            assertEquals(expectedXZ, sharedSecretB.x)
            assertEquals(expectedYZ, sharedSecretB.y)
            assertEquals(sharedSecretA, sharedSecretB)
        }
}
