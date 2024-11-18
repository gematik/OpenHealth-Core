

package de.gematik.ti.healthcard.model.exchange

import de.gematik.ti.healthcard.Requirement
import de.gematik.ti.healthcard.model.card.ICardChannel
import de.gematik.ti.healthcard.model.command.ResponseStatus
import de.gematik.ti.healthcard.model.command.executeSuccessfulOn
import de.gematik.ti.healthcard.model.command.getRandomValues
import de.gematik.ti.healthcard.model.command.select

@Requirement(
    "GS-A_4367#5",
    "GS-A_4368#4",
    sourceSpecification = "gemSpec_Krypt",
    rationale =
        "Random numbers are generated using the RNG of the health card." +
            "This generator fulfills BSI-TR-03116#3.4 PTG.2 required by gemSpec_COS#14.9.5.1",
)
fun ICardChannel.getRandom(length: Int): ByteArray {
    de.gematik.ti.healthcard.model.command.HealthCardCommand
        .select(selectParentElseRoot = false, readFirst = false)
        .executeSuccessfulOn(this)

    while (true) {
        val response =
            de.gematik.ti.healthcard.model.command.HealthCardCommand
                .getRandomValues(
                    length = length,
                ).executeOn(this)

        require(
            when (response.status) {
                ResponseStatus.SUCCESS,
                ResponseStatus.SECURITY_STATUS_NOT_SATISFIED,
                ->
                    true
                else ->
                    false
            },
        ) { "Get Random command failed with status: ${response.status}" }

        return response.apdu.data
    }
}