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

package de.gematik.openhealth.crypto

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertTrue

class CryptoJvmSmokeTest {
    @Test
    fun generateElcEphemeralPublicKey_smoke() {
        val cvc = Files.readAllBytes(cvcFixture("DEGXX820214.cvc"))

        val publicKey = generateElcEphemeralPublicKey(cvc)

        assertTrue(publicKey.isNotEmpty())
    }

    @Test
    fun generateElcEphemeralPublicKey_rejectsInvalidInput() {
        assertFails {
            generateElcEphemeralPublicKey(byteArrayOf())
        }
    }

    private fun cvcFixture(name: String): Path =
        findRepositoryRoot()
            .resolve("test-vectors")
            .resolve("cvc-chain")
            .resolve("pki_cvc_g2_input")
            .resolve("Atos_CVC-Root-CA")
            .resolve(name)

    private fun findRepositoryRoot(): Path {
        var current = Path.of("").toAbsolutePath()
        while (current.parent != null) {
            if (Files.isDirectory(current.resolve("test-vectors")) && Files.isDirectory(current.resolve("core-modules"))) {
                return current
            }
            current = current.parent
        }

        error("Could not locate repository root from ${Path.of("").toAbsolutePath()}")
    }
}
