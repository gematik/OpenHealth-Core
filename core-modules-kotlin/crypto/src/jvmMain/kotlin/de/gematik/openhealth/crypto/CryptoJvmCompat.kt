// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

@file:JvmName("CryptoKt")

package de.gematik.openhealth.crypto

import kotlin.jvm.JvmName

@JvmName("aesCmac")
@Throws(CryptoException::class)
fun aesCmacCompat(key: ByteArray, message: ByteArray, outputLength: Int): ByteArray =
    aesCmac(key, message, outputLength)

@JvmName("brainpoolP256r1Ecdh")
@Throws(CryptoException::class)
fun brainpoolP256r1EcdhCompat(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
    brainpoolP256r1Ecdh(privateKey, peerPublicKey)

@JvmName("generateBrainpoolP256r1KeyPair")
@Throws(CryptoException::class)
fun generateBrainpoolP256r1KeyPairCompat(): BrainpoolP256r1KeyPair =
    generateBrainpoolP256r1KeyPair()

@JvmName("generateElcEphemeralPublicKey")
@Throws(CryptoException::class)
fun generateElcEphemeralPublicKeyCompat(cvc: ByteArray): ByteArray =
    generateElcEphemeralPublicKey(cvc)
