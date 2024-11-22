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



package de.gematik.kmp.healthcard.model.command

private const val CLA = 0x00
private const val INS = 0x2A

/**
 * Commands representing Compute Digital Signature in gemSpec_COS#14.8.2
 */
fun HealthCardCommand.Companion.psoComputeDigitalSignature(dataToBeSigned: ByteArray) =
    HealthCardCommand(
        expectedStatus = psoComputeDigitalSignatureStatus,
        cla = CLA,
        ins = INS,
        p1 = 0x9E,
        p2 = 0x9A,
        data = dataToBeSigned,
        ne = EXPECT_ALL_WILDCARD,
    )