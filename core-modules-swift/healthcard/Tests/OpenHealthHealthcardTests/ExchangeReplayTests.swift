// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

import Foundation
import OpenHealthHealthcard
import XCTest

private struct Transcript {
    let supportsExtendedLength: Bool
    let can: String
    let keys: [String]
    let exchanges: [ExchangeEntry]
}

private struct ExchangeEntry {
    let tx: String
    let rx: String
}

private enum ReplayError: Error, CustomStringConvertible {
    case exhausted
    case mismatch(expected: String, actual: String)
    case invalidHex(String)
    case responseTooShort
    case missingHeader
    case missingField(String)

    var description: String {
        switch self {
        case .exhausted:
            return "replay exhausted"
        case let .mismatch(expected, actual):
            return "replay mismatch: expected \(expected) got \(actual)"
        case let .invalidHex(value):
            return "invalid hex value: \(value)"
        case .responseTooShort:
            return "response APDU too short"
        case .missingHeader:
            return "missing header"
        case let .missingField(field):
            return "missing \(field)"
        }
    }
}

private final class ReplayChannelCore: @unchecked Sendable {
    private let supportsExtendedLengthValue: Bool
    private let exchanges: [ExchangeEntry]
    private var index: Int = 0

    init(supportsExtendedLength: Bool, exchanges: [ExchangeEntry]) {
        self.supportsExtendedLengthValue = supportsExtendedLength
        self.exchanges = exchanges
    }

    func supportsExtendedLength() -> Bool {
        supportsExtendedLengthValue
    }

    func transmit(commandBytes: Data) throws -> Data {
        guard index < exchanges.count else {
            throw ReplayError.exhausted
        }

        let entry = exchanges[index]
        index += 1

        let txHex = toHexString(commandBytes)
        guard txHex == entry.tx else {
            throw ReplayError.mismatch(expected: entry.tx, actual: txHex)
        }

        let rxBytes = try hexToBytes(entry.rx)
        guard rxBytes.count >= 2 else {
            throw ReplayError.responseTooShort
        }

        return rxBytes
    }
}

private final class ReplayCardChannel: CardChannel, @unchecked Sendable {
    private let core: ReplayChannelCore

    init(core: ReplayChannelCore) {
        self.core = core
    }

    func supportsExtendedLength() -> Bool {
        core.supportsExtendedLength()
    }

    func transmit(command: CommandApdu) throws -> ResponseApdu {
        do {
            let responseBytes = try core.transmit(commandBytes: command.toBytes())
            return try ResponseApdu.fromBytes(bytes: responseBytes)
        } catch let apduError as ApduError {
            throw CardChannelError.Apdu(error: apduError)
        } catch {
            throw CardChannelError.Transport(code: 0, reason: "\(error)")
        }
    }
}

private struct SecureChannelHandle {
    let secureChannel: SecureChannel

    func verifyPin(_ pin: String) throws -> VerifyPinOutcome {
        let cardPin = try CardPin.fromDigits(digits: pin)
        let result = try secureChannel.verifyPin(pin: cardPin)
        return result.outcome
    }

    func getRandom(_ length: UInt32) throws -> Data {
        try secureChannel.getRandom(length: length)
    }

    func readVsd() throws -> Data {
        try secureChannel.readVsd()
    }

    func retrieveCertificate() throws -> Data {
        try secureChannel.retrieveCertificate()
    }

    func retrieveCertificateFrom(_ certificate: CertificateFile) throws -> Data {
        try secureChannel.retrieveCertificateFrom(certificate: certificate)
    }

    func unlockEgkWithPuk(_ puk: String) throws -> HealthCardResponseStatus {
        let pukPin = try CardPin.fromDigits(digits: puk)
        return try secureChannel.unlockEgkWithPuk(puk: pukPin)
    }

    func changePinWithPuk(_ puk: String, newPin: String) throws -> HealthCardResponseStatus {
        let pukPin = try CardPin.fromDigits(digits: puk)
        let newPinValue = try CardPin.fromDigits(digits: newPin)
        return try secureChannel.changePinWithPuk(puk: pukPin, newPin: newPinValue)
    }
}

private func transcriptFromJsonl(_ jsonl: String) throws -> Transcript {
    var header: [String: Any]?
    var exchanges: [ExchangeEntry] = []

    for line in jsonl.split(whereSeparator: \.isNewline) {
        let data = Data(line.utf8)
        let object = try JSONSerialization.jsonObject(with: data)
        guard let entry = object as? [String: Any] else {
            continue
        }

        guard let type = entry["type"] as? String else {
            throw ReplayError.missingField("type")
        }

        switch type {
        case "header":
            header = entry
        case "exchange":
            guard let tx = entry["tx"] as? String else {
                throw ReplayError.missingField("tx")
            }
            guard let rx = entry["rx"] as? String else {
                throw ReplayError.missingField("rx")
            }
            exchanges.append(ExchangeEntry(tx: tx, rx: rx))
        default:
            continue
        }
    }

    guard let headerEntry = header else {
        throw ReplayError.missingHeader
    }
    guard let supportsExtendedLength = headerEntry["supports_extended_length"] as? Bool else {
        throw ReplayError.missingField("supports_extended_length")
    }
    guard let can = headerEntry["can"] as? String else {
        throw ReplayError.missingField("can")
    }
    guard let keys = headerEntry["keys"] as? [String] else {
        throw ReplayError.missingField("keys")
    }

    return Transcript(
        supportsExtendedLength: supportsExtendedLength,
        can: can,
        keys: keys,
        exchanges: exchanges
    )
}

private func establishReplaySecureChannel(transcript: Transcript) throws -> SecureChannelHandle {
    let replayCore = ReplayChannelCore(
        supportsExtendedLength: transcript.supportsExtendedLength,
        exchanges: transcript.exchanges
    )
    let cardChannel = ReplayCardChannel(core: replayCore)
    let cardAccessNumber = try CardAccessNumber.fromDigits(digits: transcript.can)
    let secureChannel = try establishSecureChannelWithKeys(
        session: cardChannel,
        cardAccessNumber: cardAccessNumber,
        keys: transcript.keys
    )
    return SecureChannelHandle(secureChannel: secureChannel)
}

private func repoRootUrl() -> URL {
    var url = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 {
        url.deleteLastPathComponent()
    }
    return url
}

private func loadJsonl(named name: String) throws -> String {
    let url = repoRootUrl()
        .appendingPathComponent("test-vectors")
        .appendingPathComponent("apdu-replay")
        .appendingPathComponent(name)
    return try String(contentsOf: url, encoding: .utf8)
}

private func toHexString(_ bytes: Data) -> String {
    bytes.map { String(format: "%02X", $0) }.joined()
}

private func hexToBytes(_ value: String) throws -> Data {
    guard value.count % 2 == 0 else {
        throw ReplayError.invalidHex(value)
    }

    var bytes: [UInt8] = []
    bytes.reserveCapacity(value.count / 2)

    var index = value.startIndex
    while index < value.endIndex {
        let nextIndex = value.index(index, offsetBy: 2)
        let chunk = String(value[index..<nextIndex])
        guard let byte = UInt8(chunk, radix: 16) else {
            throw ReplayError.invalidHex(chunk)
        }
        bytes.append(byte)
        index = nextIndex
    }

    return Data(bytes)
}

final class ExchangeReplayTests: XCTestCase {
    func testReplayEstablishSecureChannel() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "establish-secure-channel.jsonl"))
        _ = try establishReplaySecureChannel(transcript: transcript)
    }

    func testReplayVerifyPin() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "verify-pin.jsonl"))
        let secureChannel = try establishReplaySecureChannel(transcript: transcript)
        let result = try secureChannel.verifyPin("123456")
        XCTAssertEqual(.success, result)
    }

    func testReplayGetRandom() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "get-random.jsonl"))
        let secureChannel = try establishReplaySecureChannel(transcript: transcript)
        let random = try secureChannel.getRandom(32)
        XCTAssertEqual(32, random.count)
    }

    func testReplayReadVsd() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "read-vsd.jsonl"))
        let secureChannel = try establishReplaySecureChannel(transcript: transcript)
        let vsd = try secureChannel.readVsd()
        XCTAssertFalse(vsd.isEmpty)
    }

    func testReplayRetrieveCertificates() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "read-certs.jsonl"))
        let secureChannel = try establishReplaySecureChannel(transcript: transcript)
        let certificate = try secureChannel.retrieveCertificate()
        XCTAssertFalse(certificate.isEmpty)

        let cvCertificate = try secureChannel.retrieveCertificateFrom(.egkAutCvcE256)
        XCTAssertFalse(cvCertificate.isEmpty)
    }

    func testReplayUnlockEgkWithPuk() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "unlock-egk-with-puk.jsonl"))
        let secureChannel = try establishReplaySecureChannel(transcript: transcript)
        let status = try secureChannel.unlockEgkWithPuk("12345678")
        XCTAssertEqual(.success, status)
    }

    func testReplayChangePinWithPuk() throws {
        let transcript = try transcriptFromJsonl(loadJsonl(named: "change-pin-with-puk.jsonl"))
        let secureChannel = try establishReplaySecureChannel(transcript: transcript)
        let status = try secureChannel.changePinWithPuk("12345678", newPin: "123456")
        XCTAssertEqual(.success, status)
    }
}
