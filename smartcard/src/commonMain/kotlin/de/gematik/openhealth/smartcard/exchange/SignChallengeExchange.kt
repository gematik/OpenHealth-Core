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

package de.gematik.openhealth.smartcard.exchange

import de.gematik.openhealth.smartcard.card.CardKey
import de.gematik.openhealth.smartcard.card.PsoAlgorithm
import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.manageSecEnvForSigning
import de.gematik.openhealth.smartcard.command.psoComputeDigitalSignature
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier

/**
 * Signs the given challenge using the card's private key for authentication.
 *
 * Relevant specifications:
 * - gemSpecObjSys#5.5 (eSign application).
 * - gemSpecCos_3.14.0#14.8.2 and gemSpec_COS_3.14.0#14.9.9.9 (PSO: COMPUTE DIGITAL SIGNATURE command and
 *   security environment configuration).
 *
 * Steps:
 * 1. Select the eSign application (DF.eSign).
 * 2. Configure the security environment for ECDSA signing.
 * 3. Perform the signing operation using the `PSO: COMPUTE DIGITAL SIGNATURE` command.
 *
 * @param challenge The challenge to be signed.
 * @return The computed digital signature.
 */

suspend fun TrustedChannelScope.signChallenge(challenge: ByteArray): ByteArray {
// REQ-BEGIN: A_20526-01, A_17205, A_17207, A_17359, A_20172, A_20700-07
// | gemF_Tokenverschlüsselung
// | Sign challenge using the health card certificate.
// REQ-BEGIN: O.Cryp_1, O.Cryp_4
// | BSI-eRp-ePA
// | Signature via ecdh ephemeral-static (one time usage)
    HealthCardCommand
        .select(
            ApplicationIdentifier(Mf.Df.Esign.AID),
        ).transmitSuccessfully()

    HealthCardCommand
        .manageSecEnvForSigning(
            PsoAlgorithm.SIGN_VERIFY_ECDSA,
            CardKey(Mf.Df.Esign.PrK.ChAutE256.KID),
            true,
        ).transmitSuccessfully()

    return HealthCardCommand
        .psoComputeDigitalSignature(challenge)
        .transmitSuccessfully()
        .apdu.data
    // REQ-END: A_20526-01, A_17205, A_17207, A_17359, A_20172, A_20700-07, O.Cryp_1, O.Cryp_4
}
