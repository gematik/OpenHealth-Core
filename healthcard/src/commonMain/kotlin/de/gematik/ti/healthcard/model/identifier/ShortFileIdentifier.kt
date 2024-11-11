/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.identifier

import org.bouncycastle.util.encoders.Hex

private const val MIN_VALUE = 1
private const val MAX_VALUE = 30

/**
 * It is possible that the attribute type shortFileIdentifier is used by the file object types.
 * Short file identifiers are used  for implicit file selection in the immediate context of a command.
 * The value of shortFileIdentifier MUST be an integer in the interval [1, 30]
 *
 * @see "ISO/IEC7816-4 und gemSpec_COS 'Spezifikation des Card Operating System'"
 */
class ShortFileIdentifier(val sfId: Int) {
    init {
        sanityCheck()
    }

    constructor(hexSfId: String) : this(Hex.decode(hexSfId)[0].toInt())

    @Suppress("ImplicitDefaultLocale")
    private fun sanityCheck() {
        require(!(sfId < MIN_VALUE || sfId > MAX_VALUE)) {
            // gemSpec_COS#N007.000
            String.format(
                "Short File Identifier out of valid range [%d,%d]",
                MIN_VALUE,
                MAX_VALUE
            )
        }
    }
}
