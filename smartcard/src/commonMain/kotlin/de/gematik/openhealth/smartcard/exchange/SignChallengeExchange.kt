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

package de.gematik.openhealth.smartcard.exchange

import de.gematik.openhealth.smartcard.Requirement
import de.gematik.openhealth.smartcard.card.CardKey
import de.gematik.openhealth.smartcard.card.HealthCardScope
import de.gematik.openhealth.smartcard.card.PsoAlgorithm
import de.gematik.openhealth.smartcard.card.SmartCard
import de.gematik.openhealth.smartcard.card.TrustedChannelScope
import de.gematik.openhealth.smartcard.cardobjects.Df
import de.gematik.openhealth.smartcard.cardobjects.Mf
import de.gematik.openhealth.smartcard.command.HealthCardCommand
import de.gematik.openhealth.smartcard.command.manageSecEnvForSigning
import de.gematik.openhealth.smartcard.command.psoComputeDigitalSignature
import de.gematik.openhealth.smartcard.command.select
import de.gematik.openhealth.smartcard.identifier.ApplicationIdentifier

@Requirement(
    "A_20526-01",
    "A_17205",
    "A_17207",
    "A_17359",
    "A_20172#3",
    "A_20700-07#1",
    sourceSpecification = "gemF_Tokenverschlüsselung",
    rationale = "Sign challenge using the health card certificate.",
)
@Requirement(
    "O.Cryp_1#1",
    "O.Cryp_4#1",
    sourceSpecification = "BSI-eRp-ePA",
    rationale = "Signature via ecdh ephemeral-static (one time usage)",
)
suspend fun TrustedChannelScope.signChallenge(challenge: ByteArray): ByteArray {
    HealthCardCommand
        .select(
            ApplicationIdentifier(Df.Esign.AID),
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
}