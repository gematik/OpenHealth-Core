@file:Suppress("MagicNumber")

package de.gematik.ti.healthcard.model.command

import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject

private const val CLA_COMMAND_CHAINING = 0x10
private const val CLA_NO_COMMAND_CHAINING = 0x00
private const val INS = 0x86
private const val NO_MEANING = 0x00

/**
 * Commands representing the General Authenticate commands in gemSpec_COS#14.7.2
 */

/**
 * UseCase: gemSpec_COS#14.7.2.1.1 PACE for end-user cards, Step 1 a
 *
 * @param commandChaining true for command chaining false if not
 */
fun HealthCardCommand.Companion.generalAuthenticate(commandChaining: Boolean) =
    HealthCardCommand(
        expectedStatus = generalAuthenticateStatus,
        cla = if (commandChaining) CLA_COMMAND_CHAINING else CLA_NO_COMMAND_CHAINING,
        ins = INS,
        p1 = NO_MEANING,
        p2 = NO_MEANING,
        data = DERTaggedObject(false, BERTags.APPLICATION, 28, DERSequence()).encoded,
        ne = NE_MAX_SHORT_LENGTH,
    )

/**
 * UseCase: gemSpec_COS#14.7.2.1.1 PACE for end-user cards, Step 2a (tagNo 1), 3a (3) , 5a (5)
 *
 * @param commandChaining true for command chaining false if not
 * @param data byteArray with data
 */
fun HealthCardCommand.Companion.generalAuthenticate(
    commandChaining: Boolean,
    data: ByteArray,
    tagNo: Int,
) = HealthCardCommand(
    expectedStatus = generalAuthenticateStatus,
    cla = if (commandChaining) CLA_COMMAND_CHAINING else CLA_NO_COMMAND_CHAINING,
    ins = INS,
    p1 = NO_MEANING,
    p2 = NO_MEANING,
    data =
        DERTaggedObject(
            true,
            BERTags.APPLICATION,
            28,
            DERTaggedObject(false, tagNo, DEROctetString(data)),
        ).encoded,
    ne = NE_MAX_SHORT_LENGTH,
)