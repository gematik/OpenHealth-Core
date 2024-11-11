@file:Suppress("ImplicitDefaultLocale")

/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.identifier

import org.bouncycastle.util.encoders.Hex

private const val AID_MIN_LENGTH = 5
private const val AID_MAX_LENGTH = 16

/**
 * An application identifier (AID) is used to address an application on the card
 */
class ApplicationIdentifier(aid: ByteArray) {
    val aid: ByteArray = aid.copyOf()
        get() =
            field.copyOf()

    init {
        require(!(aid.size < AID_MIN_LENGTH || aid.size > AID_MAX_LENGTH)) {
            // gemSpec_COS#N010.200
            String.format(
                "Application File Identifier length out of valid range [%d,%d]",
                AID_MIN_LENGTH,
                AID_MAX_LENGTH
            )
        }
    }

    constructor(hexAid: String) : this(Hex.decode(hexAid))
}
