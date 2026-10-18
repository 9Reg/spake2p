import CSpake2p
import CryptoKit
import Foundation

/// The Verifier side of a SPAKE2+ exchange (typically the server, which stores `w0` and `L`
/// but never `w1`).
///
/// Owns a handle into the Rust core, which holds the secrets and zeroises them when it is freed.
/// Single-use: `finish` may be called once, whether it succeeds or fails. Not `Sendable`.
public final class Verifier {
    private var handle: OpaquePointer?

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        if let handle { spake2p_verifier_free(handle) }
    }

    /// Answers the Prover's `shareP`. Validates `shareP` and `l`, then returns the Verifier, `shareV`
    /// (65 bytes) and `confirmV` (32 bytes) to send back.
    ///
    /// - Parameters:
    ///   - context: Must equal the Prover's, or confirmation fails.
    ///   - idProver: Must equal the Prover's.
    ///   - idVerifier: Must equal the Prover's.
    ///   - w0: The stored scalar.
    ///   - l: The registration point from ``Spake2p/register(w1:)``.
    ///   - shareP: The Prover's share.
    public static func respond(
        context: Data, idProver: Data, idVerifier: Data, w0: W0, l: L, shareP: ShareP
    ) throws(Spake2pError) -> (Verifier, shareV: ShareV, confirmV: ConfirmV) {
        _ = Spake2p.abiChecked
        let ctx = [UInt8](context), idp = [UInt8](idProver), idv = [UInt8](idVerifier)
        let lb = [UInt8](l.bytes), sp = [UInt8](shareP.bytes)
        var shareV = [UInt8](repeating: 0, count: Spake2p.pointLength)
        var confirmV = [UInt8](repeating: 0, count: Spake2p.confirmLength)
        var raw: OpaquePointer?
        let status = w0.withUnsafeBytes { b0 in
            spake2p_verifier_respond(
                ctx, ctx.count, idp, idp.count, idv, idv.count,
                b0.bindMemory(to: UInt8.self).baseAddress, b0.count, lb, lb.count, sp, sp.count,
                &raw, &shareV, shareV.count, &confirmV, confirmV.count)
        }
        try check(status)
        guard let raw else { throw .unexpected(code: -1) }
        return (Verifier(handle: raw), try ShareV(Data(shareV)), try ConfirmV(Data(confirmV)))
    }

    /// Checks the Prover's `confirmP` (32 bytes) and, only if it matches, returns the shared key.
    ///
    /// Single-use: the Verifier's state is destroyed by this call, success or failure. A second
    /// call throws ``Spake2pError/alreadyFinished``.
    public func finish(confirmP: ConfirmP) throws(Spake2pError) -> SymmetricKey {
        guard let taken = handle else { throw .alreadyFinished }
        handle = nil  // the C call frees the handle on every path
        let cp = [UInt8](confirmP.bytes)
        var key = [UInt8](repeating: 0, count: Spake2p.keyLength)
        defer { wipe(&key) }
        try check(spake2p_verifier_finish(taken, cp, cp.count, &key, key.count))
        return SymmetricKey(data: key)
    }
}
