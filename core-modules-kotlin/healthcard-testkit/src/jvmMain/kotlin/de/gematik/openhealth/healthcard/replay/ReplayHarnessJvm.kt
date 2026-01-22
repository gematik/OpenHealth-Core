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

import de.gematik.openhealth.healthcard.CardAccessNumber
import de.gematik.openhealth.healthcard.CardChannel
import de.gematik.openhealth.healthcard.CardChannelException
import de.gematik.openhealth.healthcard.CardPin
import de.gematik.openhealth.healthcard.CommandApdu
import de.gematik.openhealth.healthcard.HealthCardResponseStatus
import de.gematik.openhealth.healthcard.ResponseApdu
import de.gematik.openhealth.healthcard.CertificateFile as FfiCertificateFile
import de.gematik.openhealth.healthcard.SecureChannel
import de.gematik.openhealth.healthcard.establishSecureChannelWithKeys

actual fun establishReplaySecureChannel(transcript: Transcript): SecureChannelHandle {
    val replayCore = ReplayChannelCore(transcript.supportsExtendedLength, transcript.exchanges)
    val cardChannel = object : CardChannel {
        override fun supportsExtendedLength(): Boolean = replayCore.supportsExtendedLength()

        override fun transmit(command: CommandApdu): ResponseApdu {
            val parts = try {
                replayCore.transmit(command.toBytes())
            } catch (ex: RuntimeException) {
                throw CardChannelException.Transport(code = 0u, reason = ex.message ?: "replay failed")
            }
            return ResponseApdu(sw = parts.sw, status = HealthCardResponseStatus.UNKNOWN_STATUS, data = parts.data)
        }
    }

    val secureChannel = establishSecureChannelWithKeys(cardChannel, CardAccessNumber.fromDigits(transcript.can), transcript.keys)
    return SecureChannelHandle(secureChannel)
}

actual class SecureChannelHandle internal constructor(
    private val secureChannel: SecureChannel,
) {
    actual fun verifyPin(pin: String): VerifyPinOutcome {
        val result = secureChannel.verifyPin(CardPin.fromDigits(pin))
        return VerifyPinOutcome.valueOf(result.outcome.name)
    }

    actual fun getRandom(length: UInt): ByteArray = secureChannel.getRandom(length)

    actual fun readVsd(): ByteArray = secureChannel.readVsd()

    actual fun retrieveCertificate(): ByteArray = secureChannel.retrieveCertificate()

    actual fun retrieveCertificateFrom(certificate: CertificateFile): ByteArray {
        return secureChannel.retrieveCertificateFrom(FfiCertificateFile.valueOf(certificate.name))
    }

    actual fun unlockEgkWithPuk(puk: String): HealthCardResponseStatus {
        return secureChannel.unlockEgkWithPuk(CardPin.fromDigits(puk))
    }

    actual fun changePinWithPuk(puk: String, newPin: String): HealthCardResponseStatus {
        return secureChannel.changePinWithPuk(CardPin.fromDigits(puk), CardPin.fromDigits(newPin))
    }
}
