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
    public static let pointLength = Int(SPAKE2P_POINT_LEN)
    /// Length in bytes of a scalar (`w0`, `w1`).
    public static let scalarLength = Int(SPAKE2P_SCALAR_LEN)
    /// Length in bytes of a confirmation tag.
    public static let confirmLength = Int(SPAKE2P_CONFIRM_LEN)
    /// Length in bytes of the shared key.
    public static let keyLength = Int(SPAKE2P_KEY_LEN)
    /// Length in bytes of the PBKDF output `w0w1(fromPBKDFOutput:)` takes.
    public static let pbkdfOutputLength = Int(SPAKE2P_PBKDF_OUTPUT_LEN)

    /// The C ABI version of the linked library. It must equal the header's `SPAKE2P_ABI_VERSION`.
    public static var abiVersion: UInt32 { spake2p_abi_version() }

    /// Evaluated on first use of the library (every public entry touches it): a header and a
    /// library from different builds stop the process instead of corrupting memory.
    static let abiChecked: Void = {
        precondition(
            spake2p_abi_version() == UInt32(SPAKE2P_ABI_VERSION),
            "libspake2p ABI version \(spake2p_abi_version()) != header \(SPAKE2P_ABI_VERSION): rebuild the xcframework")
    }()

    /// Splits an 80-byte PBKDF output into `(w0, w1)` (RFC 9383 section 3.2): each 40-byte half is
    /// reduced modulo the group order. Both are secrets, held in wiped-on-release storage.
    ///
    /// - Throws: ``Spake2pError/invalidLength`` unless `output` is exactly 80 bytes;
    ///   ``Spake2pError/zeroScalar`` for a half that reduces to zero.
    public static func w0w1(fromPBKDFOutput output: Data) throws(Spake2pError) -> (w0: W0, w1: W1) {
        _ = abiChecked
        var input = [UInt8](output)
        var w0 = [UInt8](repeating: 0, count: scalarLength)
        var w1 = [UInt8](repeating: 0, count: scalarLength)
        defer { wipe(&input); wipe(&w0); wipe(&w1) }
        try check(spake2p_w0w1_from_pbkdf_output(input, input.count, &w0, w0.count, &w1, w1.count))
        return (W0(wiping: &w0), W1(wiping: &w1))
    }

    /// Computes the Verifier's registration point `L = w1·P`. The Verifier stores `(w0, L)`, never `w1`.
    ///
    /// - Throws: ``Spake2pError/zeroScalar`` or ``Spake2pError/scalarOutOfRange`` for a bad `w1`.
    public static func register(w1: W1) throws(Spake2pError) -> L {
        _ = abiChecked
        var l = [UInt8](repeating: 0, count: pointLength)
        let status = w1.withUnsafeBytes { raw in
            spake2p_register(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &l, l.count)
        }
        try check(status)
        return try L(Data(l))
    }

    /// The RFC 9383 section 3.2 recommended PBKDF input:
    /// `len(pw)||pw||len(idProver)||idProver||len(idVerifier)||idVerifier`, each length 8 bytes
    /// little-endian. It contains the password, so it is handed to `body` as a buffer that is wiped
    /// when `body` returns: feed it straight to your PBKDF, do not keep it.
    public static func withPBKDFInput<R>(
        password: Data, idProver: Data, idVerifier: Data, _ body: (UnsafeRawBufferPointer) throws -> R
    ) throws -> R {
        _ = abiChecked
        var pw = [UInt8](password)
        let idp = [UInt8](idProver)
        let idv = [UInt8](idVerifier)
        var out = [UInt8](repeating: 0, count: 24 + pw.count + idp.count + idv.count)
        defer { wipe(&pw); wipe(&out) }
        var written = 0
        try check(spake2p_pbkdf_input(pw, pw.count, idp, idp.count, idv, idv.count, &out, out.count, &written))
        return try out.withUnsafeBytes { try body(UnsafeRawBufferPointer(rebasing: $0[..<written])) }
    }
}
