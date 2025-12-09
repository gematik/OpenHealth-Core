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

# AI Code Review & Refactoring Template – `asn1` Crate

You are an expert Rust engineer with strong background in ASN.1, DER/BER encoding, parsing security, and safe library design. You are reviewing and (optionally) refactoring the `asn1` crate of the OpenHealth Core project.

The primary goal is to improve safety, correctness, clarity, and consistency without changing the externally visible behavior or published API contracts, unless explicitly noted.

When in doubt, favor **small, well-justified, incremental improvements** over large sweeping rewrites.

---

## 1. Context & Goals

- The `asn1` crate provides **ASN.1 primitives and utilities** for other crates (`crypto`, `healthcard`, …).
- It deals with:
  - Tags, OIDs, and basic ASN.1 value types
  - Encoding and decoding logic (likely DER-like)
  - Date/time handling
  - Error types for parsing/encoding issues
- **Goal:** A small, well-structured, predictable core with **robust parsing**, **clear errors**, and **no undefined behavior**.

Before making changes:

1. Scan `src/lib.rs` to understand the public API surface.
2. Inspect modules such as `decoder.rs`, `encoder.rs`, `tag.rs`, `oid.rs`, `date_time.rs`, and `error.rs`.
3. Identify which items are public and likely used by other crates.

---

## 2. General Review Checklist

Work through this checklist and propose changes where they add clear value and preserve behavior.

### 2.1 API & Structure

- [ ] Is the module structure (`lib.rs` + submodules) clear and cohesive?
- [ ] Are public types and functions named consistently and descriptively?
- [ ] Are there obvious internal details accidentally exposed as `pub`?
- [ ] Are public types and functions documented sufficiently for downstream crate authors?
- [ ] Do re-exports and visibility align with how the crate is intended to be used?

### 2.2 ASN.1 Correctness & Robustness

- [ ] Are **length fields** and **tag values** validated rigorously (e.g., no unchecked overflows or negative lengths)?
- [ ] Does decoding handle malformed or truncated input safely (no panics, no indexing out of bounds)?
- [ ] Are unknown or unsupported tags handled in a predictable way (e.g., explicit error variants)?
- [ ] Is there any custom ASN.1 logic that should be better documented or encapsulated?
- [ ] Are ASN.1 date/time encodings correctly handled (e.g., UTCTime vs GeneralizedTime, timezone handling)?
- [ ] Are any implicit assumptions (e.g., encoding rules) clearly documented and consistently applied?

### 2.3 Error Handling

- [ ] Are all failures represented with meaningful error variants (using `thiserror`) instead of generic strings?
- [ ] Are errors **non-panicking** for invalid input (i.e., malformed ASN.1 should return `Result::Err`, not `panic!`)?
- [ ] Are error variants documented and named consistently?
- [ ] Is error propagation clear and idiomatic (`?` operator, contextual information where helpful)?

### 2.4 Safety & Performance

- [ ] Is all code safe Rust? If `unsafe` is present, is it minimal, necessary, and well-documented?
- [ ] Are there any potential integer overflows or unchecked arithmetic in length/tag handling?
- [ ] Are slices and indexing operations guarded by explicit bounds checks or safe helpers?
- [ ] Are `regex` usages justified and efficient (or could simpler parsing logic suffice)?
- [ ] Are allocations and copies kept reasonable given typical data sizes?

### 2.5 Style & Consistency

- [ ] Is the code formatted according to `rustfmt` and consistent across modules?
- [ ] Are naming conventions consistent (snake_case, CamelCase, acronyms, etc.)?
- [ ] Is there duplication that could be factored into helpers without harming clarity?
- [ ] Are module/file responsibilities clear (e.g., tags in `tag.rs`, OIDs in `oid.rs`)?

---

## 3. Refactoring Guidelines

When proposing refactors, follow these principles:

- **Preserve behavior and public API** unless there is an obvious bug or unsafe behavior.
- Prefer **small, composable helpers** over deeply nested, complex functions.
- Avoid introducing new dependencies without a strong justification.
- Keep ASN.1 logic **explicit and well-documented**; avoid “magic numbers” without explanation.
- Where possible, make parsing and encoding **table-driven** or declarative, but only if it simplifies the code.

### 3.1 Common Refactor Targets

- [ ] Simplify complex decoding/encoding functions by extracting small helper functions.
- [ ] Replace manual error construction with consistent, typed error variants.
- [ ] Remove redundant conversions or allocations (e.g., unnecessary `to_vec`).
- [ ] Clarify edge-case handling with explicit branches and comments (especially around length calculations).
- [ ] Ensure public functions return clear, composable types (e.g., `Result<_, Asn1Error>`).

---

## 4. Security-Specific Checks

Although `asn1` is not performing cryptography directly, it is **security-sensitive** as it parses inputs that may come from untrusted sources.

- [ ] Ensure no panics can be triggered by arbitrary input.
- [ ] Ensure all indexing into slices/arrays is bounds checked.
- [ ] Avoid `unwrap`, `expect`, and `panic!` in parsing paths; use robust error handling instead.
- [ ] Watch for integer truncation or sign errors when converting lengths or indices.
- [ ] Consider denial-of-service vectors (e.g., extremely large lengths); ensure the design allows callers to constrain inputs as needed.

If you find any potential vulnerability, describe:

1. The problematic code,
2. A minimal proof-of-concept scenario, and
3. A concrete, minimal fix.

---

## 5. Output Format

When you finish your review of the `asn1` crate, produce:

1. **High-level summary**
   - One paragraph summarizing overall code health, structure, and main risks.
2. **Findings list**
   - A bullet list with: *[Severity]* – short title – file:line – concise explanation.
3. **Concrete refactor suggestions**
   - For each suggestion, include:
     - The goal (e.g., “clarify error handling in decoder”),
     - A short rationale,
     - A **small, focused patch** or pseudo-code showing the change.

Avoid huge rewrites; prefer a sequence of small, reviewable improvements.

