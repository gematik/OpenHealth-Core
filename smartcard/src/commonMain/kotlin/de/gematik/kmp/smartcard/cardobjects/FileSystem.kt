/*
 * Copyright (c) 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.kmp.smartcard.cardobjects

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