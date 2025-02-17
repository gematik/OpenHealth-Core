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

package de.gematik.openhealth.crypto.exchange

import de.gematik.openhealth.crypto.hexSpaceFormat
import de.gematik.openhealth.crypto.key.EcCurve
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.EcPublicKey
import de.gematik.openhealth.crypto.key.decodeFromPem
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals

private const val EC_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABJBhNcQG6SALcDA4AOUgfySk4E0o
LGTt+qP6dgv9qYMtojIMVQKNWfT14xR7LQnoSPABZlLJmWgh2cYKz3WbpVM=
-----END PUBLIC KEY-----
"""

private const val EC_PRIVATE_KEY = """
-----BEGIN EC PRIVATE KEY-----
MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIBu09g2V3coZsiK7
AUT8gHFehP7KK77g83GJH2aeYxJ1oUQDQgAEkGE1xAbpIAtwMDgA5SB/JKTgTSgs
ZO36o/p2C/2pgy2iMgxVAo1Z9PXjFHstCehI8AFmUsmZaCHZxgrPdZulUw==
-----END EC PRIVATE KEY-----
"""

class EcdhTest {
    @Test
    fun `compute secret`() =
        runTestWithProvider {
            val publicKey = EcPublicKey.decodeFromPem(EC_PUBLIC_KEY)
            val privateKey = EcPrivateKey.decodeFromPem(EC_PRIVATE_KEY)
            val result =
                EcdhSpec(EcCurve.BrainpoolP256r1)
                    .createKeyExchange(privateKey)
                    .computeSecret(publicKey)
            assertEquals(
                "A6 00 6D F4 D0 9A A6 B7 AF 41 B8 FF E6 62 78 CE B2 F6 B8 44 E1 6F 1A 73 F3 3E CB EA D3 AF 0A 7B",
                result.toHexString(hexSpaceFormat),
            )
        }
}
