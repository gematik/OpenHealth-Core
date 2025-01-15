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

package de.gematik.openhealth.smartcard.cardobjects

/**
 * Defines the file system structure and identifiers for the eGK(elektronische Gesundheitskarte) 2.1.
 *
 * This object contains constants representing File Identifiers (FIDs), Short File Identifiers (SFIDs),
 * Application Identifiers (AIDs), and Password Identifiers (PWIDs) as specified in the
 * "Spezifikation dereGK Objektsystem G2.1" (gemSpec_eGK_ObjSys_G2_1_V4_0_0).
 *
 * @see <a href="https://www.gematik.de/fileadmin/user_upload/Dokumente/eHealth-Konnektoren/Spezifikationen/gemSpec_eGK_ObjSys_G2_1_V4_0_0.pdf">gemSpec_eGK_ObjSys_G2_1_V4_0_0</a>
 */
object Ef {
    /**
     * Elementary Files (EFs) related to Card Access.
     */
    object CardAccess {
        /**
         * The File Identifier (FID) for the Card Access EF.
         *
         * This EF contains information related to the card access conditions.
         */
        const val FID = 0x011C

        /**
         * The Short File Identifier (SFID) for the Card Access EF.
         *
         * This is a shorter identifier used for faster access to the file.
         */
        const val SFID = 0x1C
    }

    /**
     * Elementary Files (EFs) related to Version 2 information.
     */
    object Version2 {
        /**
         * The File Identifier (FID) for the Version 2 EF.
         *
         * This EF contains information about the eGK version.
         */
        const val FID = 0x2F11

        /**
         * The Short File Identifier (SFID) for the Version 2 EF.
         *
         * This is a shorter identifier used for faster access to the file.
         */
        const val SFID = 0x11
    }
}

/**
 * Defines the Dedicated Files (DFs) for the eGK 2.1.
 */
object Df {
    /**
     * Dedicated Files (DFs) related to electronic signatures (eSign).
     */
    object Esign {
        /**
         * The Application Identifier (AID) for the eSign DF.
         *
         * This AID is used to select the eSign application on the card.
         */
        const val AID = "A000000167455349474E"
    }
}

/**
 * Defines the Master File (MF) and its subdirectories for the eGK 2.1.
 */
object Mf {
    /**
     * Objects related to the MrPinHome.
     */
    object MrPinHome {
        /**
         * The Password Identifier (PWID) for the MrPinHome.
         *
         * This identifier is used to reference the password for the MrPinHome.
         */
        const val PWID = 0x02
    }

    /**
     * Dedicated Files (DFs) within the Master File (MF).
     */
    object Df {
        /**
         * Dedicated Files (DFs) related to electronic signatures (eSign) within the Master File (MF).
         */
        object Esign {
            /**
             * Elementary Files (EFs) within the eSign DF.
             */
            object Ef {
                /**
                 * Elementary File (EF) for CchAutE256.
                 */
                object CchAutE256 {
                    /**
                     * The File Identifier (FID) for the CchAutE256 EF.
                     *
                     * This EF is used for the CchAutE256 functionality.
                     */
                    const val FID = 0xC504

                    /**
                     * The Short File Identifier (SFID) for the CchAutE256 EF.
                     *
                     * This is a shorter identifier used for faster access to the file.
                     */
                    const val SFID = 0x04
                }
            }

            /*** Private Keys (PrK) within the eSign DF.
             */
            object PrK {
                /**
                 * Private Key (PrK) for ChAutE256.
                 */
                object ChAutE256 {
                    /**
                     * The Key Identifier (KID) for the ChAutE256 PrK.
                     *
                     * This identifier is used to reference the ChAutE256 private key.
                     */
                    const val KID = 0x04
                }
            }
        }
    }
}