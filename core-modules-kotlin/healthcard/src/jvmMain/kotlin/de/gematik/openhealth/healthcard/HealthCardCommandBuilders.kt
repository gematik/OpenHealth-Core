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

@file:JvmName("HealthCardCommandBuilders")

package de.gematik.openhealth.healthcard

/**
 * Java-friendly wrappers for command builders to avoid Kotlin name mangling and unsigned types.
 */
@Throws(CommandBuilderException::class)
fun readSfi(sfi: Byte): HealthCardCommand =
    HealthCardCommand.readSfi(sfi.toUByte())

@Throws(CommandBuilderException::class)
fun readSfiWithOffset(sfi: Byte, offset: Int): HealthCardCommand =
    HealthCardCommand.readSfiWithOffset(sfi.toUByte(), offset)

@Throws(CommandBuilderException::class)
fun readSfiWithOffsetAndLength(sfi: Byte, offset: Int, expectedLength: Int): HealthCardCommand =
    HealthCardCommand.readSfiWithOffsetAndLength(sfi.toUByte(), offset, expectedLength.toUInt())

@Throws(CommandBuilderException::class)
fun readWithOffsetAndLength(offset: Int, expectedLength: Int): HealthCardCommand =
    HealthCardCommand.readWithOffsetAndLength(offset, expectedLength.toUInt())

@Throws(CommandBuilderException::class)
fun manageSecEnvSelectPrivateKey(keyRef: Byte, algorithmId: Byte): HealthCardCommand =
    HealthCardCommand.manageSecEnvSelectPrivateKey(keyRef.toUByte(), algorithmId.toUByte())

@Throws(CommandBuilderException::class)
fun manageSecEnvSetSignatureKeyReference(keyRef: ByteArray): HealthCardCommand =
    HealthCardCommand.manageSecEnvSetSignatureKeyReference(keyRef)

@Throws(CommandBuilderException::class)
fun generalAuthenticateMutualAuthenticationStep1(keyRef: ByteArray): HealthCardCommand =
    HealthCardCommand.generalAuthenticateMutualAuthenticationStep1(keyRef)

@Throws(CommandBuilderException::class)
fun generalAuthenticateElcStep2(pkOpponent: ByteArray): HealthCardCommand =
    HealthCardCommand.generalAuthenticateElcStep2(pkOpponent)

@Throws(CommandBuilderException::class)
fun selectAid(aid: ByteArray): HealthCardCommand =
    HealthCardCommand.selectAid(aid)

@Throws(CommandBuilderException::class)
fun selectFid(fid: Short, selectDfElseEf: Boolean): HealthCardCommand =
    HealthCardCommand.selectFid(fid.toUShort(), selectDfElseEf)

fun listPublicKeys(): HealthCardCommand =
    HealthCardCommand.listPublicKeys()

fun psoComputeDigitalSignatureCvc(cvcData: ByteArray): HealthCardCommand =
    HealthCardCommand.psoComputeDigitalSignatureCvc(cvcData)

fun internalAuthenticate(challenge: ByteArray): HealthCardCommand =
    HealthCardCommand.internalAuthenticate(challenge)
