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

package de.gematik.openhealth.crypto

import de.gematik.openhealth.crypto.internal.interop.loadNativeLibrary

/**
 * Initializes the native crypto provider by loading the native library.
 *
 * This function should be called before using any cryptographic operations that rely on the
 * native library.
 *
 * @throws RuntimeException if the native library cannot be loaded.
 */
actual suspend fun initializeNativeCryptoProvider() {
    loadNativeLibrary()
}
