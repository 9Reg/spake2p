import CSpake2p
import CryptoKit
import Foundation

/// SPAKE2+ (RFC 9383), ciphersuite P256-SHA256-HKDF-SHA256-HMAC-SHA256, implemented by the Rust
/// `spake2p` crate behind a C ABI.
///
/// Registration helpers live here; the exchange itself is `Prover` and `Verifier`.
///
/// ```swift
/// let (w0, w1) = try Spake2p.w0w1(fromPBKDFOutput: pbkdfOutput)   // 80 bytes from your PBKDF
/// let l = try Spake2p.register(w1: w1)                            // the Verifier stores (w0, l)
/// let (prover, shareP) = try Prover.start(context: ctx, idProver: a, idVerifier: b, w0: w0, w1: w1)
/// let (verifier, shareV, confirmV) = try Verifier.respond(
///     context: ctx, idProver: a, idVerifier: b, w0: w0, l: l, shareP: shareP)
/// let (confirmP, proverKey) = try prover.finish(shareV: shareV, confirmV: confirmV)
/// let verifierKey = try verifier.finish(confirmP: confirmP)
/// ```
public enum Spake2p {
    /// Length in bytes of an uncompressed SEC1 P-256 point (`shareP`, `shareV`, `L`).
    public static let pointLength = 65
    /// Length in bytes of a scalar (`w0`, `w1`), a confirmation tag and the shared key.
    public static let scalarLength = 32
    /// Length in bytes of the PBKDF output `w0w1(fromPBKDFOutput:)` takes.
    public static let pbkdfOutputLength = 80

    /// Splits an 80-byte PBKDF output into `(w0, w1)` (RFC 9383 section 3.2): each 40-byte half is
    /// reduced modulo the group order. Both are secrets; keep them out of logs.
    ///
    /// - Throws: ``Spake2pError/invalidLength`` unless `output` is exactly 80 bytes;
    ///   ``Spake2pError/zeroScalar`` for a half that reduces to zero.
    public static func w0w1(fromPBKDFOutput output: Data) throws(Spake2pError) -> (w0: Data, w1: Data) {
        var input = [UInt8](output)
        var w0 = [UInt8](repeating: 0, count: scalarLength)
        var w1 = [UInt8](repeating: 0, count: scalarLength)
        defer { wipe(&input); wipe(&w0); wipe(&w1) }
        try check(spake2p_w0w1_from_pbkdf_output(input, input.count, &w0, w0.count, &w1, w1.count))
        return (Data(w0), Data(w1))
    }

    /// Computes the Verifier's registration point `L = w1·P` (65 bytes). The Verifier stores
    /// `(w0, L)`, never `w1`.
    ///
    /// - Throws: ``Spake2pError/invalidLength``, ``Spake2pError/zeroScalar`` or
    ///   ``Spake2pError/scalarOutOfRange`` for a bad `w1`.
    public static func register(w1: Data) throws(Spake2pError) -> Data {
        var w1 = [UInt8](w1)
        var l = [UInt8](repeating: 0, count: pointLength)
        defer { wipe(&w1) }
        try check(spake2p_register(w1, w1.count, &l, l.count))
        return Data(l)
    }

    /// The RFC 9383 section 3.2 recommended PBKDF input:
    /// `len(pw)||pw||len(idProver)||idProver||len(idVerifier)||idVerifier`, each length 8 bytes
    /// little-endian. Feed it to the PBKDF you chose.
    public static func pbkdfInput(password: Data, idProver: Data, idVerifier: Data) throws(Spake2pError) -> Data {
        var pw = [UInt8](password)
        let idp = [UInt8](idProver)
        let idv = [UInt8](idVerifier)
        defer { wipe(&pw) }
        var out = [UInt8](repeating: 0, count: 24 + pw.count + idp.count + idv.count)
        defer { wipe(&out) }
        var written = 0
        try check(spake2p_pbkdf_input(pw, pw.count, idp, idp.count, idv, idv.count, &out, out.count, &written))
        return Data(out.prefix(written))
    }
}
