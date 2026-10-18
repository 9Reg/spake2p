import CSpake2p
import CryptoKit
import Foundation

/// The Prover side of a SPAKE2+ exchange (typically the client that knows the password).
///
/// Owns a handle into the Rust core, which holds the secrets and zeroises them when it is freed.
/// Single-use: `finish` may be called once, whether it succeeds or fails; after that, or after
/// the object is released, the secrets are gone. Not `Sendable`: use one instance from one task.
public final class Prover {
    private var handle: OpaquePointer?

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        if let handle { spake2p_prover_free(handle) }
    }

    /// Starts an exchange: returns the Prover and `shareP` (65 bytes) to send to the Verifier.
    ///
    /// - Parameters:
    ///   - context: Application-chosen protocol context, bound into the transcript.
    ///   - idProver: The Prover's identity. RFC 9383 recommends non-empty.
    ///   - idVerifier: The Verifier's identity. RFC 9383 recommends non-empty.
    ///   - w0: 32-byte scalar from ``Spake2p/w0w1(fromPBKDFOutput:)``.
    ///   - w1: 32-byte scalar from ``Spake2p/w0w1(fromPBKDFOutput:)``.
    public static func start(
        context: Data, idProver: Data, idVerifier: Data, w0: Data, w1: Data
    ) throws(Spake2pError) -> (Prover, shareP: Data) {
        let ctx = [UInt8](context), idp = [UInt8](idProver), idv = [UInt8](idVerifier)
        var w0 = [UInt8](w0), w1 = [UInt8](w1)
        var shareP = [UInt8](repeating: 0, count: Spake2p.pointLength)
        defer { wipe(&w0); wipe(&w1) }
        var raw: OpaquePointer?
        try check(spake2p_prover_start(
            ctx, ctx.count, idp, idp.count, idv, idv.count, w0, w0.count, w1, w1.count,
            &raw, &shareP, shareP.count))
        guard let raw else { throw .unexpected(code: -1) }
        return (Prover(handle: raw), Data(shareP))
    }

    /// Checks the Verifier's `shareV` (65 bytes) and `confirmV` (32 bytes). Only if the confirmation
    /// matches does it return `confirmP` (32 bytes, to send to the Verifier) and the shared key.
    ///
    /// Single-use: the Prover's state is destroyed by this call, success or failure. A second call
    /// throws ``Spake2pError/alreadyFinished``.
    public func finish(shareV: Data, confirmV: Data) throws(Spake2pError) -> (confirmP: Data, sharedKey: SymmetricKey) {
        guard let taken = handle else { throw .alreadyFinished }
        handle = nil  // the C call frees the handle on every path
        let sv = [UInt8](shareV), cv = [UInt8](confirmV)
        var confirmP = [UInt8](repeating: 0, count: Spake2p.scalarLength)
        var key = [UInt8](repeating: 0, count: Spake2p.scalarLength)
        defer { wipe(&key) }
        try check(spake2p_prover_finish(
            taken, sv, sv.count, cv, cv.count, &confirmP, confirmP.count, &key, key.count))
        return (Data(confirmP), SymmetricKey(data: key))
    }
}
