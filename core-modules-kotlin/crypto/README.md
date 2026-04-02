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

# Crypto Kotlin bindings (KMP)

- This module is a Kotlin Multiplatform project with JVM and Android targets.
- UniFFI-generated Kotlin sources and native libraries are consumed from `build/generated/uniffi`.
- Gradle does not generate Rust bindings itself; use the repository `just` commands first.

## Using `just` for bindings generation

- Generate Kotlin/JVM bindings for a platform/arch:

```bash
just kotlin-bindings-generate-crypto darwin aarch64 libcrypto.dylib
```

- Override output paths and cargo target dir:

```bash
OUT_ROOT=core-modules-kotlin/crypto/build/generated/uniffi \
CARGO_TARGET_DIR=core-modules-kotlin/crypto/build/cargo \
just kotlin-bindings-generate-crypto linux x86_64 libcrypto.so
```

- Publish the Kotlin module to `mavenLocal`:

```bash
just kotlin-publish-local-crypto
```
