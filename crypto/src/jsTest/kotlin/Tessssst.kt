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

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.openhealth.crypto.key.EcCurve
import de.gematik.openhealth.crypto.key.EcPrivateKey
import de.gematik.openhealth.crypto.key.decodeFromPem
import de.gematik.openhealth.crypto.key.encodeToAsn1
import de.gematik.openhealth.crypto.wrapper.OpenSslModuleFactory
import de.gematik.openhealth.crypto.wrapper.Provider
import de.gematik.openhealth.crypto.wrapper.Uint8Vector
import de.gematik.openhealth.crypto.wrapper.toByteArray
import de.gematik.openhealth.crypto.wrapper.toUint8Vector
import js.typedarrays.toUint8Array
import kotlinx.coroutines.await
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

//
//fun calculateCmac(module: EmbindModule, key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
//    val mac = module.EVP_MAC_fetch(null, "CMAC", "")
//    val macCtx = module.EVP_MAC_CTX_new(mac)
//
//    js("console.log(mac);")
//    js("console.log(macCtx);")
//
//    // Construct parameters for cipher
//    val cipherParam = module.OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC")
//    val params = module.new_OSSL_PARAM_vector()
//    params.push_back(cipherParam)
//    params.push_back(module.OSSL_PARAM_construct_end())
//
//    // Initialize MAC context with key and parameters
//    val initStatus = module.EVP_MAC_init(macCtx, key, params)
//    if (initStatus != 1) {
//        console.error("Error initializing MAC context.")
//    }
//
//    // Update MAC context with data
//    val updateStatus = module.EVP_MAC_update(macCtx, data)
//    if (updateStatus != 1) {
//        console.error("Error updating MAC context.")
//    }
//
//    // Finalize the MAC computation
//    val macResult = module.EVP_MAC_final(macCtx)
//    if (macResult == null) {
//        console.error("Error finalizing MAC.")
//    }
//
//    // Return the computed CMAC value
//    return macResult!!
//}


private const val ecPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIBu09g2V3coZsiK7
AUT8gHFehP7KK77g83GJH2aeYxJ1oUQDQgAEkGE1xAbpIAtwMDgA5SB/JKTgTSgs
ZO36o/p2C/2pgy2iMgxVAo1Z9PXjFHstCehI8AFmUsmZaCHZxgrPdZulUw==
-----END EC PRIVATE KEY-----
"""

class Tessssst {
    @Test
    fun `asdfasdf`() =
        runTest {
            val module = Provider.get()

            val alice = module.MlKemDecapsulation.create("ML-KEM-768")
            val bob = module.MlKemEncapsulation.create("ML-KEM-768", alice.getEncapsulationKey())

            val data = bob.encapsulate()

            console.log(data.sharedSecret.toByteArray().toHexString())

            val sharedSecret = alice.decapsulate(data.wrappedKey)

            console.log(sharedSecret.toByteArray().toHexString())

//            println((js("module['abc']()") as Uint8Vector).toByteArray().toHexString())

//            fn(EcPrivateKey.decodeFromPem(ecPrivateKey).encodeToAsn1().toUint8Vector() )

//            val kp = module.ECKeyPairGenerator.generateKeyPair("brainpoolP256r1")

//            kp.getPrivateKeyDER()
            //module.ECDH.create(kp.getPrivateKeyDER())

//
//
//            val x_qA = BigInteger.parseString("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",16)
//            val y_qA = BigInteger.parseString("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",16)
//            val publicKey = EcCurve.BrainpoolP256r1.point(x_qA, y_qA).uncompressed.toUint8Vector()
//
//            val a = js("module.ECPoint.create('brainpoolP256r1', publicKey)")
//            val b = js("module.ECPoint.create('brainpoolP256r1', publicKey)")
//            val c = js("a.add(b)")
//            console.log(c)
        }
}