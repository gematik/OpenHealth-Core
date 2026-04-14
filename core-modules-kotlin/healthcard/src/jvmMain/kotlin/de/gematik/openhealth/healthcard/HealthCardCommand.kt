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

package de.gematik.openhealth.healthcard

import kotlin.jvm.Throws

class HealthCardCommand private constructor(
    private val apduFactory: (Boolean) -> CommandApdu,
    private val statusMapper: (Int) -> HealthCardResponseStatus = ::defaultStatusFor,
) : AutoCloseable {

    @Throws(ExchangeException::class)
    fun execute(session: CardChannel): HealthCardResponse {
        val response = session.transmit(toApdu(session.supportsExtendedLength()))
        return HealthCardResponse(mapStatus(response.sw().toInt()), response.sw(), response.data())
    }

    @Throws(CommandBuilderException::class)
    fun mapStatus(sw: Int): HealthCardResponseStatus = statusMapper(sw)

    @Throws(ApduException::class)
    fun toApdu(supportsExtendedLength: Boolean): CommandApdu = apduFactory(supportsExtendedLength)

    fun destroy() = Unit

    override fun close() = Unit

    companion object {
        private const val CLA_STANDARD: UByte = 0x00u
        private const val CLA_COMMAND_CHAINING: UByte = 0x10u
        private const val CLA_PROPRIETARY: UByte = 0x80u

        private const val INS_SELECT: UByte = 0xA4u
        private const val INS_READ_BINARY: UByte = 0xB0u
        private const val INS_GET_DATA: UByte = 0xCAu
        private const val INS_MANAGE_SECURITY_ENVIRONMENT: UByte = 0x22u
        private const val INS_PERFORM_SECURITY_OPERATION: UByte = 0x2Au
        private const val INS_GENERAL_AUTHENTICATE: UByte = 0x86u
        private const val INS_INTERNAL_AUTHENTICATE: UByte = 0x88u

        private const val RESPONSE_TYPE_NO_RESPONSE: UByte = 0x0Cu
        private const val RESPONSE_TYPE_FCP: UByte = 0x04u
        private const val FILE_OCCURRENCE_FIRST: UByte = 0x00u
        private const val FILE_OCCURRENCE_NEXT: UByte = 0x02u
        private const val SELECTION_MODE_AID: UByte = 0x04u

        private const val SFI_MARKER: Int = 0x80
        private const val SHORT_ANY_LENGTH: UInt = 256u
        private const val EXTENDED_ANY_LENGTH: UInt = 65536u

        @Throws(CommandBuilderException::class)
        fun selectAid(aid: ByteArray): HealthCardCommand = selectAidWithOptions(aid, false, false, 0)

        @Throws(CommandBuilderException::class)
        fun selectAidWithOptions(
            aid: ByteArray,
            selectNextElseFirstOccurrence: Boolean,
            requestFcp: Boolean,
            fcpLength: Int,
        ): HealthCardCommand {
            requireNotEmpty(aid, "aid")

            val p2 =
                (
                    (if (requestFcp) RESPONSE_TYPE_FCP else RESPONSE_TYPE_NO_RESPONSE).toInt() +
                        (if (selectNextElseFirstOccurrence) FILE_OCCURRENCE_NEXT else FILE_OCCURRENCE_FIRST).toInt()
                    ).toUByte()

            return HealthCardCommand(apduFactory = { supportsExtendedLength ->
                if (requestFcp) {
                    val expectedLength = if (fcpLength <= 0) SHORT_ANY_LENGTH else requireExpectedLength(fcpLength)
                    val lengthClass = chooseExpectedLengthClass(expectedLength)
                    buildCommandApduWithDataAndExpect(
                        CLA_STANDARD,
                        INS_SELECT,
                        SELECTION_MODE_AID,
                        p2,
                        lengthClass,
                        aid.copyOf(),
                        expectedLength,
                    )
                } else {
                    buildCommandApduWithData(
                        CLA_STANDARD,
                        INS_SELECT,
                        SELECTION_MODE_AID,
                        p2,
                        chooseDataLengthClass(aid.size),
                        aid.copyOf(),
                    )
                }
            })
        }

        @Throws(CommandBuilderException::class)
        fun readSfi(sfi: Int): HealthCardCommand = readSfiWithOffsetAnyLength(sfi, 0)

        @Throws(CommandBuilderException::class)
        fun readSfiWithOffsetAndLength(sfi: Int, offset: Int, expectedLength: Int): HealthCardCommand {
            val p1 = (SFI_MARKER + requireSfi(sfi)).toUByte()
            val p2 = requireByte(offset, "offset").toUByte()
            val normalizedExpectedLength = requireExpectedLength(expectedLength)

            return HealthCardCommand(apduFactory = { supportsExtendedLength ->
                val lengthClass = chooseExpectedLengthClass(normalizedExpectedLength)
                buildCommandApduWithExpect(
                    CLA_STANDARD,
                    INS_READ_BINARY,
                    p1,
                    p2,
                    lengthClass,
                    normalizedExpectedLength,
                )
            })
        }

        fun listPublicKeys(): HealthCardCommand =
            HealthCardCommand(apduFactory = { supportsExtendedLength ->
                buildCommandApduWithExpect(
                    CLA_PROPRIETARY,
                    INS_GET_DATA,
                    0x01u,
                    0x00u,
                    if (supportsExtendedLength) LengthClass.EXTENDED else LengthClass.SHORT,
                    if (supportsExtendedLength) EXTENDED_ANY_LENGTH else SHORT_ANY_LENGTH,
                )
            })

        @Throws(CommandBuilderException::class)
        fun manageSecEnvSelectPrivateKey(keyRef: Int, algorithmId: Int): HealthCardCommand {
            val data =
                byteArrayOf(
                    0x84.toByte(),
                    0x01.toByte(),
                    requireByte(keyRef, "keyRef"),
                    0x80.toByte(),
                    0x01.toByte(),
                    requireByte(algorithmId, "algorithmId"),
                )
            return HealthCardCommand(apduFactory = {
                buildCommandApduWithData(
                    CLA_STANDARD,
                    INS_MANAGE_SECURITY_ENVIRONMENT,
                    0x41u,
                    0xA4u,
                    LengthClass.SHORT,
                    data.copyOf(),
                )
            })
        }

        @Throws(CommandBuilderException::class)
        fun manageSecEnvSetSignatureKeyReference(keyRef: ByteArray): HealthCardCommand {
            requireNotEmpty(keyRef, "keyRef")
            requireLengthFitsInOneByte(keyRef.size, "keyRef")
            val data = byteArrayOf(0x83.toByte(), keyRef.size.toByte()) + keyRef
            return HealthCardCommand(apduFactory = {
                buildCommandApduWithData(
                    CLA_STANDARD,
                    INS_MANAGE_SECURITY_ENVIRONMENT,
                    0x81u,
                    0xB6u,
                    chooseDataLengthClass(data.size),
                    data,
                )
            })
        }

        fun psoComputeDigitalSignatureCvc(dataToBeSigned: ByteArray): HealthCardCommand =
            HealthCardCommand(apduFactory = { supportsExtendedLength ->
                buildCommandApduWithData(
                    CLA_STANDARD,
                    INS_PERFORM_SECURITY_OPERATION,
                    0x00u,
                    0xBEu,
                    chooseDataLengthClass(dataToBeSigned.size),
                    dataToBeSigned.copyOf(),
                )
            })

        @Throws(CommandBuilderException::class)
        fun generalAuthenticateMutualAuthenticationStep1(keyRef: ByteArray): HealthCardCommand {
            requireNotEmpty(keyRef, "keyRef")
            return generalAuthenticate(CLA_COMMAND_CHAINING, 0xC3.toByte(), keyRef, true)
        }

        @Throws(CommandBuilderException::class)
        fun generalAuthenticateElcStep2(ephemeralPkOpponent: ByteArray): HealthCardCommand {
            requireNotEmpty(ephemeralPkOpponent, "ephemeralPkOpponent")
            return generalAuthenticate(CLA_STANDARD, 0x85.toByte(), ephemeralPkOpponent, false)
        }

        fun internalAuthenticate(challenge: ByteArray): HealthCardCommand =
            HealthCardCommand(apduFactory = { supportsExtendedLength ->
                buildCommandApduWithDataAndExpect(
                    CLA_STANDARD,
                    INS_INTERNAL_AUTHENTICATE,
                    0x00u,
                    0x00u,
                    chooseDataLengthClass(challenge.size),
                    challenge.copyOf(),
                    if (supportsExtendedLength) EXTENDED_ANY_LENGTH else SHORT_ANY_LENGTH,
                )
            })

        @Throws(CommandBuilderException::class)
        private fun generalAuthenticate(
            cla: UByte,
            innerTag: Byte,
            payload: ByteArray,
            expectResponseLength: Boolean,
        ): HealthCardCommand {
            requireLengthFitsInOneByte(payload.size, "payload")
            val inner = byteArrayOf(innerTag, payload.size.toByte()) + payload
            requireLengthFitsInOneByte(inner.size, "general authenticate body")
            val encoded = byteArrayOf(0x7C.toByte(), inner.size.toByte()) + inner
            return HealthCardCommand(apduFactory = { supportsExtendedLength ->
                if (expectResponseLength) {
                    buildCommandApduWithDataAndExpect(
                        cla,
                        INS_GENERAL_AUTHENTICATE,
                        0x00u,
                        0x00u,
                        chooseDataLengthClass(encoded.size),
                        encoded,
                        if (supportsExtendedLength) EXTENDED_ANY_LENGTH else SHORT_ANY_LENGTH,
                    )
                } else {
                    buildCommandApduWithData(
                        cla,
                        INS_GENERAL_AUTHENTICATE,
                        0x00u,
                        0x00u,
                        chooseDataLengthClass(encoded.size),
                        encoded,
                    )
                }
            })
        }

        @Throws(CommandBuilderException::class)
        private fun readSfiWithOffsetAnyLength(sfi: Int, offset: Int): HealthCardCommand {
            val p1 = (SFI_MARKER + requireSfi(sfi)).toUByte()
            val p2 = requireByte(offset, "offset").toUByte()
            return HealthCardCommand(apduFactory = { supportsExtendedLength ->
                buildCommandApduWithExpect(
                    CLA_STANDARD,
                    INS_READ_BINARY,
                    p1,
                    p2,
                    if (supportsExtendedLength) LengthClass.EXTENDED else LengthClass.SHORT,
                    if (supportsExtendedLength) EXTENDED_ANY_LENGTH else SHORT_ANY_LENGTH,
                )
            })
        }

        private fun defaultStatusFor(sw: Int): HealthCardResponseStatus =
            if (sw == 0x9000) HealthCardResponseStatus.SUCCESS else HealthCardResponseStatus.UNKNOWN_STATUS

        @Throws(CommandBuilderException::class)
        private fun requireSfi(sfi: Int): Int {
            if (sfi !in 1..30) {
                throw CommandBuilderException.InvalidArgument("sfi must be in range [1, 30]")
            }
            return sfi
        }

        @Throws(CommandBuilderException::class)
        private fun requireByte(value: Int, fieldName: String): Byte {
            if (value !in 0..0xFF) {
                throw CommandBuilderException.InvalidArgument("$fieldName must be in range [0, 255]")
            }
            return value.toByte()
        }

        @Throws(CommandBuilderException::class)
        private fun requireExpectedLength(expectedLength: Int): UInt {
            if (expectedLength !in 0..EXTENDED_ANY_LENGTH.toInt()) {
                throw CommandBuilderException.InvalidArgument("expectedLength must be in range [0, 65536]")
            }
            return expectedLength.toUInt()
        }

        @Throws(CommandBuilderException::class)
        private fun requireNotEmpty(value: ByteArray, fieldName: String) {
            if (value.isEmpty()) {
                throw CommandBuilderException.InvalidArgument("$fieldName must not be empty")
            }
        }

        @Throws(CommandBuilderException::class)
        private fun requireLengthFitsInOneByte(length: Int, fieldName: String) {
            if (length > 0xFF) {
                throw CommandBuilderException.InvalidArgument("$fieldName must be at most 255 bytes long")
            }
        }

        private fun chooseDataLengthClass(dataLength: Int): LengthClass =
            if (dataLength >= SHORT_ANY_LENGTH.toInt()) LengthClass.EXTENDED else LengthClass.SHORT

        private fun chooseExpectedLengthClass(expectedLength: UInt): LengthClass =
            if (expectedLength > SHORT_ANY_LENGTH) LengthClass.EXTENDED else LengthClass.SHORT

        @Throws(ApduException::class, CommandBuilderException::class)
        private fun buildCommandApduWithData(
            cla: UByte,
            ins: UByte,
            p1: UByte,
            p2: UByte,
            lengthClass: LengthClass,
            data: ByteArray,
        ): CommandApdu = CommandApdu.Companion.fromBytes(encodeApdu(cla, ins, p1, p2, lengthClass, data, null))

        @Throws(ApduException::class, CommandBuilderException::class)
        private fun buildCommandApduWithDataAndExpect(
            cla: UByte,
            ins: UByte,
            p1: UByte,
            p2: UByte,
            lengthClass: LengthClass,
            data: ByteArray,
            expectedLength: UInt,
        ): CommandApdu = CommandApdu.Companion.fromBytes(encodeApdu(cla, ins, p1, p2, lengthClass, data, expectedLength))

        @Throws(ApduException::class, CommandBuilderException::class)
        private fun buildCommandApduWithExpect(
            cla: UByte,
            ins: UByte,
            p1: UByte,
            p2: UByte,
            lengthClass: LengthClass,
            expectedLength: UInt,
        ): CommandApdu = CommandApdu.Companion.fromBytes(encodeApdu(cla, ins, p1, p2, lengthClass, null, expectedLength))

        @Throws(CommandBuilderException::class)
        private fun encodeApdu(
            cla: UByte,
            ins: UByte,
            p1: UByte,
            p2: UByte,
            lengthClass: LengthClass?,
            data: ByteArray?,
            expectedLength: UInt?,
        ): ByteArray {
            val body = ArrayList<Byte>()
            val payload = data?.copyOf()
            val normalizedExpectedLength = expectedLength

            when {
                payload == null && normalizedExpectedLength == null -> Unit
                payload == null && normalizedExpectedLength != null -> {
                    when (lengthClass ?: chooseExpectedLengthClass(normalizedExpectedLength)) {
                        LengthClass.SHORT -> {
                            validateShortExpectedLength(normalizedExpectedLength)
                            body += encodeShortExpectedLength(normalizedExpectedLength)
                        }
                        LengthClass.EXTENDED -> {
                            validateExtendedExpectedLength(normalizedExpectedLength)
                            body += 0x00
                            body += encodeExtendedExpectedLength(normalizedExpectedLength).toList()
                        }
                    }
                }
                payload != null && normalizedExpectedLength == null -> {
                    when (lengthClass ?: chooseDataLengthClass(payload.size)) {
                        LengthClass.SHORT -> {
                            validateShortDataLength(payload.size)
                            body += payload.size.toByte()
                            body += payload.toList()
                        }
                        LengthClass.EXTENDED -> {
                            validateExtendedDataLength(payload.size)
                            body += 0x00
                            body += encodeExtendedLength(payload.size).toList()
                            body += payload.toList()
                        }
                    }
                }
                payload != null && normalizedExpectedLength != null -> {
                    when (lengthClass ?: chooseExpectedLengthClass(normalizedExpectedLength)) {
                        LengthClass.SHORT -> {
                            validateShortDataLength(payload.size)
                            validateShortExpectedLength(normalizedExpectedLength)
                            body += payload.size.toByte()
                            body += payload.toList()
                            body += encodeShortExpectedLength(normalizedExpectedLength)
                        }
                        LengthClass.EXTENDED -> {
                            validateExtendedDataLength(payload.size)
                            validateExtendedExpectedLength(normalizedExpectedLength)
                            body += 0x00
                            body += encodeExtendedLength(payload.size).toList()
                            body += payload.toList()
                            body += encodeExtendedExpectedLength(normalizedExpectedLength).toList()
                        }
                    }
                }
            }

            return byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte()) + body.toByteArray()
        }

        @Throws(CommandBuilderException::class)
        private fun validateShortDataLength(length: Int) {
            if (length !in 1..0xFF) {
                throw CommandBuilderException.InvalidArgument("data length must be in range [1, 255] for short APDU")
            }
        }

        @Throws(CommandBuilderException::class)
        private fun validateExtendedDataLength(length: Int) {
            if (length !in 1..0xFFFF) {
                throw CommandBuilderException.InvalidArgument("data length must be in range [1, 65535] for extended APDU")
            }
        }

        @Throws(CommandBuilderException::class)
        private fun validateShortExpectedLength(expectedLength: UInt) {
            if (expectedLength > SHORT_ANY_LENGTH) {
                throw CommandBuilderException.InvalidArgument("expectedLength must be in range [0, 256] for short APDU")
            }
        }

        @Throws(CommandBuilderException::class)
        private fun validateExtendedExpectedLength(expectedLength: UInt) {
            if (expectedLength !in 1u..EXTENDED_ANY_LENGTH) {
                throw CommandBuilderException.InvalidArgument("expectedLength must be in range [1, 65536] for extended APDU")
            }
        }

        private fun encodeShortExpectedLength(expectedLength: UInt): Byte =
            if (expectedLength == 0u || expectedLength == SHORT_ANY_LENGTH) 0x00 else expectedLength.toByte()

        private fun encodeExtendedLength(length: Int): ByteArray =
            byteArrayOf(((length ushr 8) and 0xFF).toByte(), (length and 0xFF).toByte())

        private fun encodeExtendedExpectedLength(expectedLength: UInt): ByteArray {
            if (expectedLength == EXTENDED_ANY_LENGTH) {
                return byteArrayOf(0x00, 0x00)
            }
            val length = expectedLength.toInt()
            return byteArrayOf(((length ushr 8) and 0xFF).toByte(), (length and 0xFF).toByte())
        }
    }
}
