/*
 * Copyright 2025 gematik GmbH
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

package de.gematik.openhealth.examples

import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.crypto.initializeNativeCryptoProvider
import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.card.useHealthCard
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.exchange.HealthCardVerifyPinResult
import de.gematik.openhealth.smartcard.exchange.establishTrustedChannel
import de.gematik.openhealth.smartcard.exchange.retrieveCertificate
import de.gematik.openhealth.smartcard.exchange.verifyPin

class CallbackSmartCard(val transmit: suspend (apdu: ByteArray) -> ByteArray) : SmartCard() {
    inner class CommunicationScope : SmartCard.CommunicationScope {
        override val cardIdentifier: String
            get() = "WebSocket Card"
        override val supportsExtendedLength: Boolean
            get() = true

        override suspend fun transmit(commandApdu: CardCommandApdu): CardResponseApdu {
            return CardResponseApdu(this@CallbackSmartCard.transmit(commandApdu.apdu))
        }
    }

    override suspend fun <T> connect(block: suspend SmartCard.CommunicationScope.() -> T): T {
        return block(CommunicationScope())
    }
}

@OptIn(ExperimentalStdlibApi::class)
suspend fun readHealthCard(
    can: String,
    pin: String,
    transmit: suspend (apdu: ByteArray) -> ByteArray
): String {
    initializeNativeCryptoProvider()
    return CallbackSmartCard(transmit).connect {
        useHealthCard {
            with(establishTrustedChannel(can)) {
                val verifyPinResult = verifyPin(pin)
                when (verifyPinResult) {
                    is HealthCardVerifyPinResult.CardBlocked -> error("Card blocked")
                    is HealthCardVerifyPinResult.WrongSecretWarning -> error("Wrong secret - ${verifyPinResult.retriesLeft} retries left")
                    else -> retrieveCertificate().readSubject()
                }
            }
        }
    }
}

private fun ByteArray.readSubject(): String {
    return "TODO"
}
