<!--
SPDX-FileCopyrightText: Copyright 2025 gematik GmbH

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

# gematik openHealth - Core Modules

OpenHealth provides open-source software components for TI-related development.
This repository offers reusable modules for smartcard access, cryptography, and efficient interoperability between Rust
and other platforms.

**The project is in active, early-stage development; APIs and modules may change
without prior notice.**

## Project Overview

- `core-modules/`: Rust crates for ASN.1 handling, cryptography and healthcard
  functionality.
- `core-modules-kotlin/`: Kotlin/JVM bindings and examples that integrate the
  Rust modules into JVM-based applications.
- `core-modules-swift/`: Swift/iOS interoperability artifacts (UniFFI + xcframework).
- `docs/`: Additional documentation, interoperability notes and project
  specific guides.

## Target Platforms

We aim to support a broad set of operating systems and architectures, including:

| Platform      | Architectures | Runtimes (examples)              | Supported?   |
|---------------|---------------|----------------------------------|--------------|
| Linux         | x86_64        | Native Rust, JVM (tests/tooling) | Experimental |
| Windows       | x86_64        | Native Rust, JVM (tests/tooling) | Not yet      |
| macOS         | arm64         | Native Rust, JVM (tests/tooling) | Experimental |
| Android       | arm64, x86_64 | JVM (Android, via JNI/NDK)       | Not yet      |
| iOS           | arm64         | Native                           | Not yet      |
| iOS Simulator | arm64         | Native                           | Not yet      |

## Contributing

If you want to contribute, please refer to the
[Contribution Guidelines](./CONTRIBUTING.md) for information about workflows,
code style and testing expectations.

## Documentation

See [docs/README.md](docs/README.md).

## License

<!--REUSE-IgnoreStart-->
Copyright 2025 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE.md) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for
   use. These are regularly typical conditions in connection with open source or free software. Programs
   described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
   associated documentation files (the "Software"), to deal in the Software without restriction, including without
   limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
   Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial
       portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not
       limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The
       authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising
       from, out of or in connection with the software or the use or other dealings with the software, whether in an
       action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily quality assured and
       without the character of a liable product. For this reason, gematik does not provide any support or other user
       assistance (unless otherwise stated in individual cases and without justification of a legal obligation).
       Furthermore, there is no claim to further development and adaptation of the results to a more current state of
       the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without
   prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account,
   especially when troubleshooting, for security analyses and possible adjustments.

<!--REUSE-IgnoreEnd-->
