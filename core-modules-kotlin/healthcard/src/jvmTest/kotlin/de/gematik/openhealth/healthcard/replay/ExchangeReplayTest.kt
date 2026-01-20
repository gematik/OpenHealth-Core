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

package de.gematik.openhealth.healthcard.replay

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ExchangeReplayTest {
    @Test
    fun replayEstablishSecureChannel() {
        val transcript = transcriptFromJsonl(JSONL_ESTABLISH_SECURE_CHANNEL)
        establishReplaySecureChannel(transcript)
    }

    @Test
    fun replayVerifyPin() {
        val transcript = transcriptFromJsonl(JSONL_VERIFY_PIN)
        val secureChannel = establishReplaySecureChannel(transcript)
        val result = secureChannel.verifyPin("123456")
        assertEquals(VerifyPinOutcome.SUCCESS, result)
    }

    @Test
    fun replayGetRandom() {
        val transcript = transcriptFromJsonl(JSONL_GET_RANDOM)
        val secureChannel = establishReplaySecureChannel(transcript)
        val random = secureChannel.getRandom(32u)
        assertEquals(32, random.size)
    }

    @Test
    fun replayReadVsd() {
        val transcript = transcriptFromJsonl(JSONL_READ_VSD)
        val secureChannel = establishReplaySecureChannel(transcript)
        val vsd = secureChannel.readVsd()
        assertTrue(vsd.isNotEmpty())
    }

    @Test
    fun replayRetrieveCertificates() {
        val transcript = transcriptFromJsonl(JSONL_READ_CERTS)
        val secureChannel = establishReplaySecureChannel(transcript)
        val cert = secureChannel.retrieveCertificate()
        assertTrue(cert.isNotEmpty())

        val cvCert = secureChannel.retrieveCertificateFrom(CertificateFile.EGK_AUT_CVC_E256)
        assertTrue(cvCert.isNotEmpty())
    }
}
