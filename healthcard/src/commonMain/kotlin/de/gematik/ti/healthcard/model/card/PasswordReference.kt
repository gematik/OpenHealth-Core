/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.card

/**
 * A password can be a regular password or multireference password
 *
 * * A "regular password" is used to store a secret, which is usually only known to one cardholder. The COS will allow certain services only if this secret has been successfully presented as part of a user verification. The need for user verification can be turned on (enable) or turned off (disable).
 * * A multireference password allows the use of a secret, which is stored as an at-tributary in a regular password (see (N015.200)), but under conditions that deviate from those of the regular password.
 *
 * @see "gemSpec_COS 'Spezifikation des Card Operating System'"
 */

private const val MIN_PWD_ID = 0
private const val MAX_PWD_ID = 31

class PasswordReference(val pwdId: Int) : ICardKeyReference {
    init {
        require(!(pwdId < MIN_PWD_ID || pwdId > MAX_PWD_ID)) {
            // gemSpec_COS#N015.000
            "Password ID out of range [$MIN_PWD_ID,$MAX_PWD_ID]"
        }
    }

    // gemSpec_COS#N072.800
    override fun calculateKeyReference(dfSpecific: Boolean): Int =
        pwdId + if (dfSpecific) {
            ICardKeyReference.DF_SPECIFIC_PWD_MARKER
        } else {
            0
        }
}
