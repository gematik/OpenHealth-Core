package de.gematik.openhealth.smartcard.card

import de.gematik.openhealth.smartcard.HealthCardTestScope
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.HealthCardResponseStatus
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class HealthCardScopeTest {
    @Test
    fun testTransmitSuccessfully() =
        runTest {
            val healthCardScope = HealthCardTestScope().healthCardScope()
            val command =
                HealthCardCommand(
                    expectedStatus =
                        mapOf(
                            0x9000 to HealthCardResponseStatus.SUCCESS,
                            0x6200 to HealthCardResponseStatus.UNKNOWN_STATUS,
                        ),
                    cla = 0x00,
                    ins = 0x00,
                    p1 = 0x00,
                    p2 = 0x00,
                    data = byteArrayOf(0x00),
                )

            val response =
                with(healthCardScope) {
                    command.transmitSuccessfully()
                }
            assertEquals(HealthCardResponseStatus.SUCCESS, response.status)
        }
}
