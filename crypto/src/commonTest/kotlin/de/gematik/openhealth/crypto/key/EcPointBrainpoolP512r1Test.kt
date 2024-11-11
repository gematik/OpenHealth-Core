package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals

@Suppress("ktlint:standard:max-line-length")
class EcPointBrainpoolP512r1Test {
    private val curve = EcCurve.BrainpoolP512r1

    @Test
    fun `test vector - rfc6932`() =
        runTestWithProvider {
            // Test vector according to https://datatracker.ietf.org/doc/html/rfc6932

            val dA =
                BigInteger.parseString(
                    "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
                    16,
                )
            val xQa =
                BigInteger.parseString(
                    "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD",
                    16,
                )
            val yQa =
                BigInteger.parseString(
                    "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7",
                    16,
                )

            val dB =
                BigInteger.parseString(
                    "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429",
                    16,
                )
            val xQb =
                BigInteger.parseString(
                    "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F",
                    16,
                )
            val yQb =
                BigInteger.parseString(
                    "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA",
                    16,
                )

            val expectedXZ =
                BigInteger.parseString(
                    "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F",
                    16,
                )
            val expectedYZ =
                BigInteger.parseString(
                    "7DB71C3DEF63212841C463E881BDCF055523BD368240E6C3143BD8DEF8B3B3223B95E0F53082FF5E412F4222537A43DF1C6D25729DDB51620A832BE6A26680A2",
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
