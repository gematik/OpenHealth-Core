package de.gematik.openhealth.smartcard.model.command

import de.gematik.openhealth.smartcard.TestChannel
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.data.getExpectedApdu
import de.gematik.openhealth.smartcard.hexSpaceFormat
import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier
import de.gematik.openhealth.smartcard.identifier.FileIdentifier
import de.gematik.openhealth.smartcard.parameter
import de.gematik.openhealth.smartcard.runParametrizedTest
import kotlinx.coroutines.test.runTest
import kotlin.test.DefaultAsserter.assertEquals
import kotlin.test.Test
import kotlin.test.assertEquals

const val SELECT_PARENT_ELSE_ROOT = "selectParentElseRoot"
const val READ_FIRST = "readFirst"
const val SELECT_NEXT_OCCURRENCE = "selectNextElseFirstOccurrence"
const val REQUEST_FCP = "requestFcp"

class SelectCommandTest {
    private val parameters = arrayOf(true, false)

    @Test
    fun shouldEqualSelectCommand_SelectParentElseRoot_ReadFirst() {
        val parameterCombinations =
            listOf(
                mapOf(SELECT_PARENT_ELSE_ROOT to true, READ_FIRST to true),
                mapOf(SELECT_PARENT_ELSE_ROOT to true, READ_FIRST to false),
                mapOf(SELECT_PARENT_ELSE_ROOT to false, READ_FIRST to true),
                mapOf(SELECT_PARENT_ELSE_ROOT to false, READ_FIRST to false),
            )

        runParametrizedTest(*parameterCombinations.toTypedArray()) {
            val selectParentElseRoot = parameter<Boolean>()
            val readFirst = parameter<Boolean>()

            val expectedAPDU =
                getExpectedApdu(
                    "SELECTCOMMAND_APDU-1",
                    mapOf(
                        SELECT_PARENT_ELSE_ROOT to selectParentElseRoot,
                        READ_FIRST to readFirst,
                    ),
                )
            val command = HealthCardCommand.select(selectParentElseRoot, readFirst)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
    }

    @Test
    fun shouldEqualSelectCommand_ApplicationIdentifier() {
        val aid = ApplicationIdentifier(byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x00, 0x01, 0x02))

        runTest {
            val expectedAPDU = getExpectedApdu("SELECTCOMMAND_APDU-2")

            val command = HealthCardCommand.select(aid)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
            )
        }
    }

    @Test
    fun shouldEqualSelectCommand_FileIdentifier_SelectDfElseEf() {
        runParametrizedTest(parameters) {
            val selectDfElseEf = parameter<Boolean>()

            val fid = FileIdentifier(byteArrayOf(0x2F, 0x01))
            val expectedAPDU =
                getExpectedApdu(
                    "SELECTCOMMAND_APDU-4",
                    selectDfElseEf,
                )

            val command = HealthCardCommand.select(fid, selectDfElseEf)

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
    }

    @Test
    fun shouldEqualSelectCommand_ApplicationIdentifier_WithOptions() {
        val parameterCombinations =
            sequenceOf(
                mapOf(SELECT_NEXT_OCCURRENCE to true, REQUEST_FCP to true),
                mapOf(SELECT_NEXT_OCCURRENCE to true, REQUEST_FCP to false),
                mapOf(SELECT_NEXT_OCCURRENCE to false, REQUEST_FCP to true),
                mapOf(SELECT_NEXT_OCCURRENCE to false, REQUEST_FCP to false),
            )

        runParametrizedTest(*parameterCombinations.toList().toTypedArray()) {
            val selectNextOccurrence = parameter<Boolean>()
            val requestFCP = parameter<Boolean>()

            val aid =
                ApplicationIdentifier(byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x00, 0x01, 0x02))
            val expectedAPDU =
                getExpectedApdu(
                    "SELECTCOMMAND_APDU-3",
                    mapOf(
                        SELECT_NEXT_OCCURRENCE to selectNextOccurrence,
                        REQUEST_FCP to requestFCP,
                    ),
                )

            val command =
                HealthCardCommand.select(
                    aid,
                    selectNextOccurrence,
                    requestFCP,
                    fcpLength = if (requestFCP) 0x64 else 0,
                )

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
    }

    @Test
    fun shouldEqualSelectCommand_FileIdentifier_WithOptions() {
        val parameterCombinations =
            sequenceOf(
                mapOf(SELECT_NEXT_OCCURRENCE to true, REQUEST_FCP to true),
                mapOf(SELECT_NEXT_OCCURRENCE to true, REQUEST_FCP to false),
                mapOf(SELECT_NEXT_OCCURRENCE to false, REQUEST_FCP to true),
                mapOf(SELECT_NEXT_OCCURRENCE to false, REQUEST_FCP to false),
            )

        runParametrizedTest(*parameterCombinations.toList().toTypedArray()) {
            val selectNextOccurrence = parameter<Boolean>()
            val requestFCP = parameter<Boolean>()

            val fid = FileIdentifier(byteArrayOf(0x2F, 0x01))
            val expectedAPDU =
                getExpectedApdu(
                    "SELECTCOMMAND_APDU-5",
                    mapOf(
                        SELECT_NEXT_OCCURRENCE to selectNextOccurrence,
                        REQUEST_FCP to requestFCP,
                    ),
                )

            val command =
                HealthCardCommand.select(
                    fid,
                    selectNextOccurrence,
                    requestFCP,
                    fcpLength = if (requestFCP) 0x64 else 0,
                )

            assertEquals(
                expectedAPDU,
                TestChannel().test(command).toHexString(hexSpaceFormat),
                message,
            )
        }
    }
}