

package de.gematik.ti.healthcard.model.card

/**
 * Represent a specific PSO Algorithm
 *
 * @see "ISO/IEC7816-4 und gemSpec_COS 'Spezifikation des Card Operating System'"
 */
enum class PsoAlgorithm(
    val identifier: Int,
) {
    SIGN_VERIFY_ECDSA(0x00),
}