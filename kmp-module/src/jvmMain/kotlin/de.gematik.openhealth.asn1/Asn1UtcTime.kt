package de.gematik.openhealth.asn1


class Asn1UtcTime {
    companion object {
        init {
            System.loadLibrary("asn1_jni")
        }

        @JvmStatic
        external fun parse(input: String): String
    }
}
