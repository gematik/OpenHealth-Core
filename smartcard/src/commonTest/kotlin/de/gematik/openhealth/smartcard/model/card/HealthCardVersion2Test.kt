/*
 * Copyright (c) 2024 gematik GmbH
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

package de.gematik.openhealth.smartcard.model.card

import de.gematik.openhealth.smartcard.card.parseHealthCardVersion2
import de.gematik.openhealth.smartcard.hexSpaceFormat
import kotlin.test.Test
import kotlin.test.assertEquals

class HealthCardVersion2Test {
    @Test
    fun `parse version of health card`() {
        val version2 =
            parseHealthCardVersion2(
                (
                    "EF 2B C0 03 02 00 00 C1 03 04 03 02 C2 10 45 47 4B 47 32 20 20 20 " +
                        "20 20 20 20 20 01 03 04 C4 03 01 00 00 C5 03 02 00 00 C7 03 01 00 00"
                ).hexToByteArray(hexSpaceFormat),
            )
        assertEquals(
            "02 00 00",
            version2.fillingInstructionsEfAtrVersion.toHexString(hexSpaceFormat),
        ) // C5
        assertEquals(
            "",
            version2.fillingInstructionsEfEnvironmentSettingsVersion.toHexString(hexSpaceFormat),
        ) // C3
        assertEquals(
            "01 00 00",
            version2.fillingInstructionsEfGdoVersion.toHexString(hexSpaceFormat),
        ) // C4
        assertEquals(
            "",
            version2.fillingInstructionsEfKeyInfoVersion.toHexString(hexSpaceFormat),
        ) // C6
        assertEquals(
            "01 00 00",
            version2.fillingInstructionsEfLoggingVersion.toHexString(hexSpaceFormat),
        ) // C7
        assertEquals(
            "02 00 00",
            version2.fillingInstructionsVersion.toHexString(hexSpaceFormat),
        ) // C0
        assertEquals(
            "04 03 02",
            version2.objectSystemVersion.toHexString(hexSpaceFormat),
        ) // C1
        assertEquals(
            "45 47 4B 47 32 20 20 20 20 20 20 20 20 01 03 04",
            version2.productIdentificationObjectSystemVersion.toHexString(hexSpaceFormat),
        ) // C2
    }
}
