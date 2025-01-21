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


package de.gematik.openhealth.smartcard.model.exchange

import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.smartcard.HealthCardTestScope
import de.gematik.openhealth.smartcard.card.PaceKey
import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.card.TrustedChannelScopeImpl
import de.gematik.openhealth.smartcard.command.CardCommandApdu
import de.gematik.openhealth.smartcard.command.CardResponseApdu
import de.gematik.openhealth.smartcard.hexUppercaseFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

@OptIn(ExperimentalCryptoApi::class)
class SecureMessagingTest {
    private val keyEnc: ByteArray = "68406B4162100563D9C901A6154D2901".hexToByteArray(hexUppercaseFormat)
    private val keyMac: ByteArray = "73FF268784F72AF833FDC9464049AFC9".hexToByteArray(hexUppercaseFormat)
    private val paceKey = PaceKey(SecretKey(keyEnc), SecretKey(keyMac))
    private val healthCardTestScope = HealthCardTestScope()

    private fun createTrustedChannel(): TrustedChannelScopeImpl =
        TrustedChannelScopeImpl(scope = healthCardTestScope, paceKey = paceKey)

    // test Case 1: |CLA|INS|P1|P2|
    @Test
    fun testEncryptionCase1() {
        val secureMessaging = createTrustedChannel()
        val commandApdu = CardCommandApdu.ofOptions(0x01, 0x02, 0x03, 0x04, null)
        val expectedEncryptedApdu = "0D0203040A8E08D92B4FDDC2BBED8C00"
        val encryptedCommandApdu = secureMessaging.encrypt(commandApdu)
        assertEquals(
            expectedEncryptedApdu,
            encryptedCommandApdu.apdu.toHexString(hexUppercaseFormat)
        )
        assertFails {
            secureMessaging.encrypt(encryptedCommandApdu)
        }
    }

    // test Case 2s: |CLA|INS|P1|P2|LE|
    @Test
    fun testEncryptionCase2s() {
        val secureMessaging = createTrustedChannel()
        val commandApdu = CardCommandApdu.ofOptions(0x01, 0x02, 0x03, 0x04, 127)
        val expectedEncryptedApdu = "0D02030400000D97017F8E0871D8E0418DAE20F30000"
        val encryptedCommandApdu = secureMessaging.encrypt(commandApdu)
        assertEquals(
            expectedEncryptedApdu,
            encryptedCommandApdu.apdu.toHexString(hexUppercaseFormat)
        )
    }

    // test Case 2e: |CLA|INS|P1|P2|EXTLE|
    @Test
    fun testEncryptionCase2e() {
        val secureMessaging = createTrustedChannel()
        val commandApdu = CardCommandApdu.ofOptions(0x01, 0x02, 0x03, 0x04, 257)
        val expectedEncryptedApdu = "0D02030400000E970201018E089F3EDDFBB1D3971D0000"
        val encryptedCommandApdu = secureMessaging.encrypt(commandApdu)
        assertEquals(
            expectedEncryptedApdu,
            encryptedCommandApdu.apdu.toHexString(hexUppercaseFormat)
        )
    }

    // test Case 3s. : |CLA|INS|P1|P2|LC|DATA|
    @Test
    fun testEncryptionCase3s() {
        val cmdData = byteArrayOf(0x05, 0x06, 0x07, 0x08, 0x09, 0x0a)
        val secureMessaging = createTrustedChannel()
        val commandApdu = CardCommandApdu.ofOptions(0x01, 0x02, 0x03, 0x04, cmdData, null)
        val expectedEncryptedApdu =
            "0D0203041D871101496C26D36306679609665A385C54DB378E08E7AAD918F260D8EF00"
        val encryptedCommandApdu = secureMessaging.encrypt(commandApdu)
        assertEquals(
            expectedEncryptedApdu,
            encryptedCommandApdu.apdu.toHexString(hexUppercaseFormat)
        )
    }

    // test Case 4s. : |CLA|INS|P1|P2|LC|DATA|LE|
    @Test
    fun testEncryptionCase4s() {
        val secureMessaging = createTrustedChannel()
        val cmdData = byteArrayOf(0x05, 0x06, 0x07, 0x08, 0x09, 0x0a)
        val commandApdu = CardCommandApdu.ofOptions(0x01, 0x02, 0x03, 0x04, cmdData, 127)
        val expectedEncryptedApdu =
            "0D020304000020871101496C26D36306679609665A385C54DB3797017F8E0863D541F262BD445A0000"
        val encryptedCommandApdu = secureMessaging.encrypt(commandApdu)
        assertEquals(
            expectedEncryptedApdu,
            encryptedCommandApdu.apdu.toHexString(hexUppercaseFormat)
        )
    }

    // test Case 4e: |CLA|INS|P1|P2|EXT('00')|LC|DATA|LE|
    @Test
    fun testEncryptionCase4e() {
        val secureMessaging = createTrustedChannel()
        val cmdData = ByteArray(256)
        val commandApdu = CardCommandApdu.ofOptions(0x01, 0x02, 0x03, 0x04, cmdData, 127)
        val expectedEncryptedApdu =
            (

                    "0D02030400012287820111013297D4AA774AB26AF8AD539C0A829BCA4D222D3EE2DB100CF86D7DB5A1FAC12B7623328DEFE3F6FDD41A993A" +
                        "C917BC17B364C3DD24740079DE60A3D0231A7185D36A77D37E147025913ADA00CD07736CFDE0DB2E0BB09B75C5773607E54A9D84181A" +
                        "CBC6F7726762A8BCE324C0B330548114154A13EDDBFF6DCBC3773DCA9A8494404BE4A5654273F9C2B9EBE1BD615CB39FFD0D3F2A0EEA" +
                        "29AA10B810D53EDB550FB741A68CC6B0BDF928F9EB6BC238416AACB4CF3002E865D486CF42D762C86EEBE6A2B25DECE2E88D569854A0" +
                        "7D3F146BC134BAF08B6EDCBEBDFF47EBA6AC7B441A1642B03253B588C49B69ABBEC92BA1723B7260DE8AD6158873141AFA7C70CFCF12" +
                        "5BA1DF77CA48025D049FCEE497017F8E0856332C83EABDF93C0000"
                )
        val encryptedCommandApdu = secureMessaging.encrypt(commandApdu)
        assertEquals(
            expectedEncryptedApdu,
            encryptedCommandApdu.apdu.toHexString(hexUppercaseFormat)
        )
    }

    // test Case 1: DO99|DO8E|SW1SW2
    @Test
    fun shouldDecryptDo99Apdu() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt = CardResponseApdu("990290008E08087631D746F872729000".hexToByteArray(hexUppercaseFormat))
        val decryptedApdu : CardResponseApdu = secureMessaging.decrypt(apduToDecrypt)
        val expectedDecryptedApdu = CardResponseApdu(byteArrayOf(0x90.toByte(), 0x00))
        assertEquals(
            expectedDecryptedApdu.bytes.toHexString(hexUppercaseFormat),
            decryptedApdu.bytes.toHexString(hexUppercaseFormat)
        )
    }

    // test Case 2: DO87|DO99|DO8E|SW1SW2
    @Test
    fun shouldDecryptDo87Apdu() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt =
            CardResponseApdu("871101496c26d36306679609665a385c54db37990290008E08B7E9ED2A0C89FB3A9000".hexToByteArray(hexUppercaseFormat))
        val decryptedApdu: CardResponseApdu = secureMessaging.decrypt(apduToDecrypt)
        val expectedDecryptedApdu = CardResponseApdu("05060708090a9000".hexToByteArray(hexUppercaseFormat))
        assertEquals(
            expectedDecryptedApdu.bytes.toHexString(hexUppercaseFormat),
            decryptedApdu.bytes.toHexString(hexUppercaseFormat)
        )
    }

    @Test
    fun decryptShouldFailWithMissingStatusBytes() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt =
            CardResponseApdu("871101496c26d36306679609665a385c54db378E08B7E9ED2A0C89FB3A9000".hexToByteArray(hexUppercaseFormat))

        assertFails {
            secureMessaging.decrypt(apduToDecrypt)
        }
    }

    @Test
    fun decryptShouldFailWithMissingStatus() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt =
            CardResponseApdu("871101496c26d36306679609665a385c54db37990290008E08B7E9ED2A0C89FB3A".hexToByteArray(hexUppercaseFormat))

        assertFails {
            secureMessaging.decrypt(apduToDecrypt)
        }
    }

    @Test
    fun decryptShouldFailWithWrongCCS() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt =
            CardResponseApdu("871101496c26d36306679609665a385c54db37990290008E08A7E9ED2A0C89FB3A9000".hexToByteArray(hexUppercaseFormat))

        assertFails {
            secureMessaging.decrypt(apduToDecrypt)
        }
    }

    @Test
    fun decryptShouldFailWithMissingCCS() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt =
            CardResponseApdu("871101496c26d36306679609665a385c54db37990290009000".hexToByteArray(hexUppercaseFormat))

        assertFails {
            secureMessaging.decrypt(apduToDecrypt)
        }
    }

    @Test
    fun decryptShouldFailWithNotEncryptedApdu() {
        val secureMessaging = createTrustedChannel()
        val apduToDecrypt = CardResponseApdu(byteArrayOf(0x90.toByte(), 0x00))

        assertFails {
            secureMessaging.decrypt(apduToDecrypt)
        }
    }
}
