@file:Suppress("MagicNumber")

package de.gematik.ti.healthcard.model.command

import de.gematik.ti.healthcard.model.card.CardKey
import de.gematik.ti.healthcard.model.card.PsoAlgorithm
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject

/**
 * Commands representing Manage Security Environment command in gemSpec_COS#14.9.9
 */

private const val CLA = 0x00
private const val INS = 0x22
private const val MODE_SET_SECRET_KEY_OBJECT_P1 = 0xC1
private const val MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2 = 0xA4
private const val MODE_SET_PRIVATE_KEY_P1 = 0x41
private const val MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION = 0xB6

/**
 * Use case Key Selection for symmetric card connection without curves gemSpec_COS#14.9.9.7
 */
fun HealthCardCommand.Companion.manageSecEnvWithoutCurves(
    cardKey: CardKey,
    dfSpecific: Boolean,
    oid: ByteArray?,
) = HealthCardCommand(
    expectedStatus = manageSecurityEnvironmentStatus,
    cla = CLA,
    ins = INS,
    p1 = MODE_SET_SECRET_KEY_OBJECT_P1,
    p2 = MODE_AFFECTED_LIST_ELEMENT_IS_EXT_AUTH_P2,
    data =
        // '80 I2OS(OctetLength(OID), 1) || OID || 83 01 || keyRef'
        DERTaggedObject(false, 0, DEROctetString(oid)).encoded +
            DERTaggedObject(
                false,
                3,
                DEROctetString(byteArrayOf(cardKey.calculateKeyReference(dfSpecific).toByte())),
            ).encoded,
)

/**
 * Use cases Key Selection for authentication and encryption gemSpec_COS#14.9.9.9
 */
fun HealthCardCommand.Companion.manageSecEnvForSigning(
    psoAlgorithm: PsoAlgorithm,
    key: CardKey,
    dfSpecific: Boolean,
) = HealthCardCommand(
    expectedStatus = manageSecurityEnvironmentStatus,
    cla = CLA,
    ins = INS,
    p1 = MODE_SET_PRIVATE_KEY_P1,
    p2 = MODE_AFFECTED_LIST_ELEMENT_IS_SIGNATURE_CREATION,
    data =
        // '8401||keyRef||8001 algId'
        DERTaggedObject(
            false,
            4,
            DEROctetString(byteArrayOf(key.calculateKeyReference(dfSpecific).toByte())),
        ).encoded +
            DERTaggedObject(
                false,
                0,
                DEROctetString(byteArrayOf(psoAlgorithm.identifier.toByte())),
            ).encoded,
)