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

package de.gematik.openhealth.smartcard.card

/**
 * Represents a specific PSO (Perform Security Operation) Algorithm
 *
 * ISO/IEC7816-4
 * gemSpec_COS_3.14.0#14.8 PSO Algorithm
 */
enum class PsoAlgorithm(
    val identifier: Int,
) {
    SIGN_VERIFY_ECDSA(0x00),
}
