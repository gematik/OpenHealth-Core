package de.gematik.openhealth.healthcard

import uniffi.health_card.CardChannel
import uniffi.health_card.TrustedChannel
import uniffi.health_card.establishTrustedChannel

/**
 * Convenience accessors for the UniFFI generated API so the rest of the project does not
 * have to worry about loading the native library up front.
 */
object TrustedChannelFactory {
    fun establish(
        cardChannel: CardChannel,
        cardAccessNumber: String,
    ): TrustedChannel {
        //HealthCardNative.ensureLoaded()
        return establishTrustedChannel(cardChannel, cardAccessNumber)
    }
}
