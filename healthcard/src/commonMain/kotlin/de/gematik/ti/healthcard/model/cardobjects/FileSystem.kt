/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.ti.healthcard.model.cardobjects

/**
 * eGK 2.1 file system objects
 * @see gemSpec_eGK_ObjSys_G2_1_V4_0_0 'Spezifikation der eGK Objektsystem G2.1'
 */

object Ef {
    object CardAccess {
        const val FID = 0x011C
        const val SFID = 0x1C
    }

    object Version2 {
        const val FID = 0x2F11
        const val SFID = 0x11
    }
}

object Df {
    object Esign {
        const val AID = "A000000167455349474E"
    }
}

object Mf {
    object MrPinHome {
        const val PWID = 0x02
    }
    object Df {
        object Esign {
            object Ef {
                object CchAutE256 {
                    const val FID = 0xC504
                    const val SFID = 0x04
                }
            }
            object PrK {
                object ChAutE256 {
                    const val KID = 0x04
                }
            }
        }
    }
}
