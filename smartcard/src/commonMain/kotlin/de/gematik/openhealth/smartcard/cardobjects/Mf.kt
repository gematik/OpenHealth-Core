/*
 * Copyright 2025 gematik GmbH
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

package de.gematik.openhealth.smartcard.cardobjects

/**
 * eGK 2.1 file system objects as specified in the
 * "Spezifikation der eGK Objektsystem G2.1" (gemSpec_eGK_ObjSys_G2_1_4.7.1).
 *
 * @see <a href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_eGK_ObjSys_G2_1/latest/">gemSpec_eGK_ObjSys_G2_1</a>
 */
object Mf {
    /**
     * Elementary Files (EFs) within the Master File (MF).
     */
    object Ef {
        /**
         * MF / EF.CardAccess is necessary for secure contactless communication using the PACE protocol.
         *
         * @see gemSpec_eGK_ObjSys_G2_1 Section 5.3.2
         */
        object CardAccess {
            const val FID = 0x011C
            const val SFID = 0x1C
        }

        /**
         * MF / EF.Version2 contains the version numbers as well as product identifiers.
         *
         * @see gemSpec_eGK_ObjSys_G2_1 Section 5.3.8
         */
        object Version2 {
            const val FID = 0x2F11
            const val SFID = 0x11
        }
    }

    /**
     * MF / MRPIN.home is a multi-reference password object for unlocking keys and content of the eGK.
     *
     * @see gemSpec_eGK_ObjSys_G2_1 Section 5.3.10
     */
    object MrPinHome {
        const val PWID = 0x02
    }

    /**
     * Dedicated Files (DFs) within the Master File (MF).
     */
    object Df {
        /**
         * DF.ESIGN contains eSign-related objects.
         *
         * @see gemSpec_eGK_ObjSys_G2_1 Section 5.5
         */
        object Esign {
            const val AID = "A000000167455349474E"

            /**
             * Elementary Files (EFs) within the eSign DF.
             */
            object Ef {
                /**
                 * MF / DF.ESIGN / EF.C.CH.AUT.E256 contains the X.509 authentication certificate
                 * for elliptic curve cryptography with the public key PuK.CH.AUT.E256.
                 *
                 * @see gemSpec_eGK_ObjSys_G2_1 Section 5.5.9
                 */
                object CchAutE256 {
                    const val FID = 0xC504
                    const val SFID = 0x04
                }
            }

            /**
             * Private Keys (PrK) within the eSign DF.
             */
            object PrK {
                /**
                 * MF / DF.ESIGN / PrK.CH.AUT.E256 references the private key for elliptic curve cryptography.
                 * The public part corresponding to this private key is located in EF.C.CH.AUT.E256.
                 *
                 * @see gemSpec_eGK_ObjSys_G2_1 Section 5.5.13
                 */
                object ChAutE256 {
                    const val KID = 0x04
                }
            }
        }

        /**
         * DF.HCA contains health card application-related files.
         *
         * @see gemSpec_eGK_ObjSys_G2_1 Section 5.4
         */
        object HCA {
            const val AID = "D27600000102"

            /**
             * Elementary Files (EFs) within the HCA DF.
             */
            object Ef {
                /**
                 * MF / DF.HCA / EF.PD contains the personal data of the cardholder.
                 *
                 * @see gemSpec_eGK_ObjSys_G2_1 Section 5.4.4
                 */
                object Pd {
                    const val FID = 0xD001
                    const val SFID = 0x01
                }

                /**
                 * MF / DF.HCA / EF.StatusVD contains the status of VD and PD.
                 *
                 * @see gemSpec_eGK_ObjSys_G2_1 Section 5.4.7
                 */
                object StatusVD {
                    const val FID = 0xD00C
                    const val SFID = 0x0C
                }

                /**
                 * MF / DF.HCA / EF.VD contains the VD of the cardholder.
                 *
                 * @see gemSpec_eGK_ObjSys_G2_1 Section 5.4.9
                 */
                object Vd {
                    const val FID = 0xD002
                    const val SFID = 0x02
                }
            }
        }
    }
}
