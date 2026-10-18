import CryptoKit
import Foundation
import Testing

@testable import Spake2p

private let ctx = Data("swift test".utf8)
private let idP = Data("client".utf8)
private let idV = Data("server".utf8)

private struct Registered {
    let w0: Data, w1: Data, l: Data
    init(seed: UInt8) throws {
        (w0, w1) = try Spake2p.w0w1(fromPBKDFOutput: Data(repeating: seed, count: 80))
        l = try Spake2p.register(w1: w1)
    }
}

private func keyBytes(_ k: SymmetricKey) -> Data { k.withUnsafeBytes { Data($0) } }

private func flip(_ d: Data, _ i: Int = 0) -> Data {
    var d = d
    d[d.startIndex + i] ^= 1
    return d
}

/// Runs a full exchange; the Prover and Verifier may be set up with different parameters.
private func exchange(
    prover: Registered, verifier: Registered,
    proverContext: Data = ctx, verifierContext: Data = ctx,
    proverIdP: Data = idP, verifierIdP: Data = idP,
    proverIdV: Data = idV, verifierIdV: Data = idV
) throws -> (SymmetricKey, SymmetricKey) {
    let (p, shareP) = try Prover.start(
        context: proverContext, idProver: proverIdP, idVerifier: proverIdV, w0: prover.w0, w1: prover.w1)
    let (v, shareV, confirmV) = try Verifier.respond(
        context: verifierContext, idProver: verifierIdP, idVerifier: verifierIdV,
        w0: verifier.w0, l: verifier.l, shareP: shareP)
    let (confirmP, pk) = try p.finish(shareV: shareV, confirmV: confirmV)
    return (pk, try v.finish(confirmP: confirmP))
}

@Suite struct Spake2pTests {
    @Test func roundTrip() throws {
        let r = try Registered(seed: 7)
        let (pk, vk) = try exchange(prover: r, verifier: r)
        #expect(keyBytes(pk) == keyBytes(vk))
        #expect(keyBytes(pk).count == 32)
        #expect(keyBytes(pk) != Data(count: 32))
        let (pk2, _) = try exchange(prover: r, verifier: r)
        #expect(keyBytes(pk) != keyBytes(pk2), "fresh randomness per run")
    }

    @Test func wrongPassword() throws {
        #expect(throws: Spake2pError.confirmationFailed) {
            _ = try exchange(prover: Registered(seed: 7), verifier: Registered(seed: 8))
        }
    }

    @Test func tamperedShareV() throws {
        let r = try Registered(seed: 7)
        let (p, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        let (_, shareV, confirmV) = try Verifier.respond(
            context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: shareP)
        // Flipping a bit of the y coordinate gives an off-curve point; of the x coordinate, almost
        // always an off-curve point too: either way the exchange must fail.
        #expect(throws: Spake2pError.self) { _ = try p.finish(shareV: flip(shareV, 40), confirmV: confirmV) }
    }

    @Test func tamperedConfirmV() throws {
        let r = try Registered(seed: 7)
        let (p, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        let (_, shareV, confirmV) = try Verifier.respond(
            context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: shareP)
        #expect(throws: Spake2pError.confirmationFailed) {
            _ = try p.finish(shareV: shareV, confirmV: flip(confirmV, 31))
        }
    }

    @Test func tamperedShareP() throws {
        let r = try Registered(seed: 7)
        let (_, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        #expect(throws: Spake2pError.notOnCurve) {
            _ = try Verifier.respond(
                context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: flip(shareP, 64))
        }
    }

    @Test func tamperedConfirmP() throws {
        let r = try Registered(seed: 7)
        let (p, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        let (v, shareV, confirmV) = try Verifier.respond(
            context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: shareP)
        let (confirmP, _) = try p.finish(shareV: shareV, confirmV: confirmV)
        #expect(throws: Spake2pError.confirmationFailed) { _ = try v.finish(confirmP: flip(confirmP, 5)) }
    }

    @Test func contextAndIdentityBinding() throws {
        let r = try Registered(seed: 7)
        let other = Data("other".utf8)
        #expect(throws: Spake2pError.confirmationFailed) {
            _ = try exchange(prover: r, verifier: r, verifierContext: other)
        }
        #expect(throws: Spake2pError.confirmationFailed) {
            _ = try exchange(prover: r, verifier: r, verifierIdP: other)
        }
        #expect(throws: Spake2pError.confirmationFailed) {
            _ = try exchange(prover: r, verifier: r, proverIdV: other)
        }
    }

    @Test func emptyContextAndIdentitiesWork() throws {
        let r = try Registered(seed: 9)
        let (pk, vk) = try exchange(
            prover: r, verifier: r, proverContext: Data(), verifierContext: Data(),
            proverIdP: Data(), verifierIdP: Data(), proverIdV: Data(), verifierIdV: Data())
        #expect(keyBytes(pk) == keyBytes(vk))
    }

    @Test func invalidShares() throws {
        let r = try Registered(seed: 7)
        let (_, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        func respond(_ share: Data) throws -> Verifier {
            try Verifier.respond(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: share).0
        }
        var compressed = shareP
        compressed[0] = 0x02
        #expect(throws: Spake2pError.invalidEncoding) { _ = try respond(compressed) }
        #expect(throws: Spake2pError.invalidLength) { _ = try respond(shareP.prefix(33)) }
        #expect(throws: Spake2pError.invalidLength) { _ = try respond(shareP + Data([0])) }
        #expect(throws: Spake2pError.notOnCurve) { _ = try respond(flip(shareP, 64)) }
        #expect(throws: Spake2pError.invalidEncoding) { _ = try respond(Data(count: 65)) }
        // Invalid L as well.
        #expect(throws: Spake2pError.notOnCurve) {
            _ = try Verifier.respond(
                context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: flip(r.l, 64), shareP: shareP)
        }
    }

    @Test func invalidShareVAtProver() throws {
        let r = try Registered(seed: 7)
        let (p, _) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        #expect(throws: Spake2pError.invalidEncoding) {
            _ = try p.finish(shareV: Data(count: 65), confirmV: Data(count: 32))
        }
        // The failed finish consumed the Prover.
        #expect(throws: Spake2pError.alreadyFinished) {
            _ = try p.finish(shareV: Data(count: 65), confirmV: Data(count: 32))
        }
    }

    @Test func finishIsSingleUse() throws {
        let r = try Registered(seed: 7)
        let (p, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        let (v, shareV, confirmV) = try Verifier.respond(
            context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: shareP)
        let (confirmP, _) = try p.finish(shareV: shareV, confirmV: confirmV)
        #expect(throws: Spake2pError.alreadyFinished) { _ = try p.finish(shareV: shareV, confirmV: confirmV) }
        _ = try v.finish(confirmP: confirmP)
        #expect(throws: Spake2pError.alreadyFinished) { _ = try v.finish(confirmP: confirmP) }
    }

    @Test func failedVerifierFinishConsumes() throws {
        let r = try Registered(seed: 7)
        let (p, shareP) = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        let (v, shareV, confirmV) = try Verifier.respond(
            context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, l: r.l, shareP: shareP)
        let (confirmP, _) = try p.finish(shareV: shareV, confirmV: confirmV)
        #expect(throws: Spake2pError.confirmationFailed) { _ = try v.finish(confirmP: flip(confirmP)) }
        // A correct tag now cannot revive it.
        #expect(throws: Spake2pError.alreadyFinished) { _ = try v.finish(confirmP: confirmP) }
    }

    @Test func unfinishedObjectsFreeCleanly() throws {
        let r = try Registered(seed: 7)
        for _ in 0..<100 {
            _ = try Prover.start(context: ctx, idProver: idP, idVerifier: idV, w0: r.w0, w1: r.w1)
        }
    }

    @Test func pbkdfLengthErrors() {
        for n in [0, 1, 79, 81, 160] {
            #expect(throws: Spake2pError.invalidLength, "length \(n)") {
                _ = try Spake2p.w0w1(fromPBKDFOutput: Data(repeating: 1, count: n))
            }
        }
        #expect(throws: Spake2pError.invalidLength) { _ = try Spake2p.register(w1: Data(count: 31)) }
        #expect(throws: Spake2pError.zeroScalar) { _ = try Spake2p.register(w1: Data(count: 32)) }
        #expect(throws: Spake2pError.scalarOutOfRange) {
            _ = try Spake2p.register(w1: Data(repeating: 0xff, count: 32))
        }
        #expect(throws: Spake2pError.zeroScalar) {
            _ = try Spake2p.w0w1(fromPBKDFOutput: Data(count: 80))
        }
    }

    @Test func pbkdfInputLayout() throws {
        let out = try Spake2p.pbkdfInput(password: Data("pw".utf8), idProver: Data("a".utf8), idVerifier: Data())
        var want = Data()
        for s in ["pw", "a", ""] {
            var n = UInt64(s.utf8.count).littleEndian
            want.append(Data(bytes: &n, count: 8))
            want.append(Data(s.utf8))
        }
        #expect(out == want)
    }

    /// RFC 9383 Appendix C vector: the Rust core derives the vector's L from its w1.
    @Test func rfcVectorL() throws {
        let path = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("vectors/rfc9383-p256-sha256-hkdf-hmac.json")
        let json = try #require(
            JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
        func hex(_ k: String) throws -> Data {
            let s = try #require(json[k] as? String)
            var d = Data()
            var i = s.startIndex
            while i < s.endIndex {
                let j = s.index(i, offsetBy: 2)
                d.append(try #require(UInt8(s[i..<j], radix: 16)))
                i = j
            }
            return d
        }
        let l = try Spake2p.register(w1: hex("w1"))
        #expect(l == (try hex("L")))
        // The vector's identities run end to end too (random x and y, so only agreement is checked).
        let w0 = try hex("w0"), w1 = try hex("w1")
        let c = Data((json["context"] as? String ?? "").utf8)
        let (p, shareP) = try Prover.start(
            context: c, idProver: Data("client".utf8), idVerifier: Data("server".utf8), w0: w0, w1: w1)
        let (v, shareV, confirmV) = try Verifier.respond(
            context: c, idProver: Data("client".utf8), idVerifier: Data("server".utf8), w0: w0, l: l, shareP: shareP)
        let (confirmP, pk) = try p.finish(shareV: shareV, confirmV: confirmV)
        #expect(keyBytes(pk) == keyBytes(try v.finish(confirmP: confirmP)))
    }
}
