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

package de.gematik.openhealth.smartcard.exchange

import de.gematik.openhealth.asn1.Asn1Decoder
import de.gematik.openhealth.asn1.Asn1Encoder
import de.gematik.openhealth.asn1.Asn1Tag
import de.gematik.openhealth.asn1.Asn1Type
import de.gematik.openhealth.asn1.readInt
import de.gematik.openhealth.asn1.readObjectIdentifier
import de.gematik.openhealth.asn1.writeObjectIdentifier
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.EcCurve

@OptIn(ExperimentalCryptoApi::class)
class PaceInfo(
    val protocolId: String,
    val curve: EcCurve,
) {
    val protocolIdBytes: ByteArray =
        Asn1Encoder()
            .write { writeObjectIdentifier(protocolId) }
            .let { it.copyOfRange(2, it.size) }
}

/**
 * Parses the PACE information from an ASN.1 encoded byte array.
 *
 * This function extracts:
 * 1. The protocol identifier (OID).
 * 2. The parameter ID, which determines the elliptic curve.
 *
 * References:
 * - gemSpec_COS#14.8.2.2: PACE Protocol Details
 *
 * @param asn1 The ASN.1 encoded PACE information.
 * @return A [PaceInfo] object containing the protocol ID and curve.
 * @throws IllegalArgumentException If the parameter ID is not supported.
 */
@OptIn(ExperimentalCryptoApi::class)
fun parsePaceInfo(asn1: ByteArray): PaceInfo =
    Asn1Decoder(asn1).read {
        advanceWithTag(Asn1Type.SET, Asn1Tag.CONSTRUCTED) {
            advanceWithTag(Asn1Type.SEQUENCE, Asn1Tag.CONSTRUCTED) {
                // Step 1: Read protocol identifier (OID)
                val protocolId = readObjectIdentifier()

                // Step 2: Read and ignore the first integer
                readInt()

                // Step 3: Read the parameter ID and map to an elliptic curve
                val parameterId = readInt()

                val curve =
                    supportedCurves[parameterId]
                        ?: fail { "Unsupported parameter ID: $parameterId" }

                // Ensure no unexpected data exists
                skipToEnd()

                // Step 4: Create and return the PACE info
                PaceInfo(protocolId, curve)
            }
        }
    }

// Mapping of parameter IDs to supported elliptic curves
@OptIn(ExperimentalCryptoApi::class)
private val supportedCurves =
    mapOf(
        13 to EcCurve.BrainpoolP256r1,
        16 to EcCurve.BrainpoolP384r1,
        17 to EcCurve.BrainpoolP512r1,
    )
