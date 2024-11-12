/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.card

private const val MIN_KEY_ID = 2
private const val MAX_KEY_ID = 28

/**
 * Class applies for symmetric keys and private keys.
 */
@Suppress("ImplicitDefaultLocale")
class CardKey(private val keyId: Int) : ICardKeyReference {
    init {
        require(!(keyId < MIN_KEY_ID || keyId > MAX_KEY_ID)) {
            // gemSpec_COS#N016.400 and #N017.100
            "Key ID out of range [$MIN_KEY_ID,$MAX_KEY_ID]"
        }
    }

    override fun calculateKeyReference(dfSpecific: Boolean): Int {
        // gemSpec_COS#N099.600
        var keyReference = keyId
        if (dfSpecific) {
            keyReference += ICardKeyReference.DF_SPECIFIC_PWD_MARKER
        }
        return keyReference
    }
}
