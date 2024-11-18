

package de.gematik.ti.healthcard.model.exchange

import de.gematik.ti.healthcard.Requirement
import de.gematik.ti.healthcard.model.card.CardKey
import de.gematik.ti.healthcard.model.card.ICardChannel
import de.gematik.ti.healthcard.model.card.PsoAlgorithm
import de.gematik.ti.healthcard.model.cardobjects.Df
import de.gematik.ti.healthcard.model.command.executeSuccessfulOn
import de.gematik.ti.healthcard.model.command.manageSecEnvForSigning
import de.gematik.ti.healthcard.model.command.psoComputeDigitalSignature
import de.gematik.ti.healthcard.model.command.select
import de.gematik.ti.healthcard.model.identifier.ApplicationIdentifier

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
fun ICardChannel.signChallenge(challenge: ByteArray): ByteArray {
    de.gematik.ti.healthcard.model.command.HealthCardCommand
        .select(
            ApplicationIdentifier(Df.Esign.AID),
        ).executeSuccessfulOn(this)

    de.gematik.ti.healthcard.model.command.HealthCardCommand
        .manageSecEnvForSigning(
            PsoAlgorithm.SIGN_VERIFY_ECDSA,
            CardKey(de.gematik.ti.healthcard.model.cardobjects.Mf.Df.Esign.PrK.ChAutE256.KID),
            true,
        ).executeSuccessfulOn(this)

    return de.gematik.ti.healthcard.model.command.HealthCardCommand
        .psoComputeDigitalSignature(challenge)
        .executeSuccessfulOn(this)
        .apdu.data
}