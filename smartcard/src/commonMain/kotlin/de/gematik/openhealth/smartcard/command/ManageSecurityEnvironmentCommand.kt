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

@file:Suppress("MagicNumber")

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.asn1.writeTaggedObject
import de.gematik.openhealth.smartcard.card.CardKey
import de.gematik.openhealth.smartcard.card.PsoAlgorithm

/**
 * Commands representing Manage Security Environment command in gemSpec_COS#14.9.9
 */

private const val CLA = 0x00
private const val INS = 0x22
private const val MODE_SET_SECRET_KEY_OBJECT_P1 = 0xC1
private const val MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2 = 0xA4
private const val MODE_SET_PRIVATE_KEY_P1 = 0x41
private const val MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION = 0xB6

/**
 * Creates a [HealthCardCommand] for the MANAGE SECURITY ENVIRONMENT command
 * without curves. (gemSpec_COS#14.9.9.7)
 *
 * This command is used to set up the security environment for external
 * authentication.
 *
 * @param cardKey The [CardKey] to use.
 * @param dfSpecific `true` if the key is DF-specific, `false` otherwise.
 * @param oid The Object Identifier (OID)for the protocol.
 */
fun HealthCardCommand.Companion.manageSecEnvWithoutCurves(
    cardKey: CardKey,
    dfSpecific: Boolean,
    oid: ByteArray,
) = HealthCardCommand(
    expectedStatus = manageSecurityEnvironmentStatus,
    cla = CLA,
    ins = INS,
    p1 = MODE_SET_SECRET_KEY_OBJECT_P1,
    p2 = MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2,
    data =
        Asn1Encoder().write {
            // '80 I2OS(OctetLength(OID), 1) || OID
            writeTaggedObject(0, Asn1Tag.CONTEXT_SPECIFIC) {
                write(oid)
            }
            // '83 01 || keyRef'
            writeTaggedObject(3, Asn1Tag.CONTEXT_SPECIFIC) {
                write(byteArrayOf(cardKey.calculateKeyReference(dfSpecific).toByte()))
            }
        },
)

/**
 * Creates a [HealthCardCommand] for the MANAGE SECURITY ENVIRONMENT command
 * for signing. (gemSpec_COS#14.9.9.9)
 *
 * This command is used to set up the security environment for external
 * authentication.
 *
 *  @param psoAlgorithm The [PsoAlgorithm].
 *  @param key The [CardKey].
 *  @param dfSpecific `true` if the key is DF-specific, `false` otherwise
 */
fun HealthCardCommand.Companion.manageSecEnvForSigning(
    psoAlgorithm: PsoAlgorithm,
    key: CardKey,
    dfSpecific: Boolean,
): HealthCardCommand =
    HealthCardCommand(
        expectedStatus = manageSecurityEnvironmentStatus,
        cla = CLA,
        ins = INS,
        p1 = MODE_SET_PRIVATE_KEY_P1,
        p2 = MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION,
        data =
            Asn1Encoder().write {
                // '8401 || keyRef'
                writeTaggedObject(4, Asn1Tag.CONTEXT_SPECIFIC) {
                    write(key.calculateKeyReference(dfSpecific).toByte())
                }
                // '8001 || algId'
                writeTaggedObject(0, Asn1Tag.CONTEXT_SPECIFIC) {
                    write(psoAlgorithm.identifier.toByte())
                }
            },
    )
