package de.gematik.kmp.crypto

import kotlin.random.Random

abstract class SecureRandom : Random()

expect fun secureRandom(): SecureRandom