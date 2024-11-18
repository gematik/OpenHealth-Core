

package de.gematik.ti.healthcard.model.card

/**
 * interface that identifier:
 *
 * - symmetric authentication object,
 * - symmetric map connection object,
 * - or private key object
 */
interface ICardKeyReference {
    fun calculateKeyReference(dfSpecific: Boolean): Int

    companion object {
        const val DF_SPECIFIC_PWD_MARKER = 0x80
    }
}