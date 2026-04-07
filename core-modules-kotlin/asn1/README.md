<!--
SPDX-FileCopyrightText: Copyright 2026 gematik GmbH

SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*******

For additional notes and disclaimer from gematik and in case of changes by gematik,
find details in the "Readme" file.
-->

# ASN.1 Kotlin bindings (KMP)

- This module is a Kotlin Multiplatform project with a JVM target.
- UniFFI bindings and native libraries are expected to be provided by the shared pipeline and placed under:
  - Kotlin/Java sources: `${OUT_ROOT}/kotlin`
  - Native artifacts and scaffolding: `${OUT_ROOT}/resources/<platform-id>/`
  - Android JNI libs (optional): `${OUT_ROOT}/android-jni/`
- Gradle does not build Rust or run UniFFI; it consumes the pre-generated artifacts from the locations above.

## Using `just` for bindings generation

From the repository root:

```bash
# platform: linux | windows | darwin
# arch: x86_64 | aarch64
just kotlin-bindings-generate asn1 darwin aarch64 libasn1.dylib
```

Pick a different profile (default is `release`):

```bash
just kotlin-bindings-generate asn1 darwin aarch64 libasn1.dylib debug
```

Android native libraries (Linux only):

```bash
just kotlin-bindings-generate-android asn1
```

Android debug JNI libs:

```bash
just kotlin-bindings-generate-android asn1 debug
```
