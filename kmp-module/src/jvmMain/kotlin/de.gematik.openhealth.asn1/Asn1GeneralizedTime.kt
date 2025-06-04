package de.gematik.openhealth.asn1

class Asn1GeneralizedTime {
    companion object {
        init {
            System.loadLibrary("asn1_jni")
        }

        @JvmStatic
        external fun parse(input: String): String
    }
}
