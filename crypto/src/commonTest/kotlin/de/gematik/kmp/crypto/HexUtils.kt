package de.gematik.kmp.crypto

val hexSpaceFormat =
    HexFormat {
        bytes.byteSeparator = " "
        upperCase = true
    }