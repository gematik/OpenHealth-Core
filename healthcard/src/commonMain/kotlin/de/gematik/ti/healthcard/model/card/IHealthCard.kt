

package de.gematik.ti.healthcard.model.card

import de.gematik.ti.healthcard.model.command.CommandApdu
import de.gematik.ti.healthcard.model.command.ResponseApdu

interface IHealthCard {
    fun transmit(apduCommand: CommandApdu): ResponseApdu
}