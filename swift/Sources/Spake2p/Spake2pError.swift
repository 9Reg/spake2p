import CSpake2p
import Foundation

/// Why a SPAKE2+ operation failed. Mirrors `spake2p::Error` in the Rust core. Carries no secret data.
public enum Spake2pError: Error, Equatable, Sendable {
    /// A byte string had the wrong length (shares and `L` are 65 bytes, scalars 32, confirmation
    /// tags 32, PBKDF output 80).
    case invalidLength
    /// A point was not in uncompressed SEC1 form (compressed, hybrid and identity encodings are refused).
    case invalidEncoding
    /// A point was well-formed but is not on the P-256 curve.
    case notOnCurve
    /// A received or computed point was the identity element.
    case identityPoint
    /// A scalar was greater than or equal to the group order (never silently reduced).
    case scalarOutOfRange
    /// `w0` or `w1` was zero.
    case zeroScalar
    /// The peer's confirmation tag did not match: wrong password, wrong context or identity, or
    /// tampering. The cause is deliberately not distinguished.
    case confirmationFailed
    /// The operating system's random number generator failed.
    case rng
    /// The stored verification value `L` is not a valid point. A local fault with the record, never
    /// a bad peer share.
    case invalidRecord
    /// `finish` was already called on this object. A Prover or Verifier is single-use.
    case alreadyFinished
    /// A status the Rust core reported that has no case above (an ABI mismatch or an internal bug).
    case unexpected(code: Int32)

    init(status: Int32) {
        // The C constants (header enum) are imported as `Int`; match on them, never on literals.
        switch Int(status) {
        case SPAKE2P_ERR_INVALID_LENGTH: self = .invalidLength
        case SPAKE2P_ERR_INVALID_ENCODING: self = .invalidEncoding
        case SPAKE2P_ERR_NOT_ON_CURVE: self = .notOnCurve
        case SPAKE2P_ERR_IDENTITY_POINT: self = .identityPoint
        case SPAKE2P_ERR_SCALAR_OUT_OF_RANGE: self = .scalarOutOfRange
        case SPAKE2P_ERR_ZERO_SCALAR: self = .zeroScalar
        case SPAKE2P_ERR_CONFIRMATION_FAILED: self = .confirmationFailed
        case SPAKE2P_ERR_RNG: self = .rng
        case SPAKE2P_ERR_INVALID_RECORD: self = .invalidRecord
        default: self = .unexpected(code: status)
        }
    }
}

/// Throws the matching `Spake2pError` unless `status` is `SPAKE2P_OK`.
@inline(__always)
func check(_ status: Int32) throws(Spake2pError) {
    if Int(status) != SPAKE2P_OK { throw Spake2pError(status: status) }
}

/// Overwrites `bytes` with zeros in a way the optimiser may not remove (best effort: copies made
/// elsewhere by the runtime are out of reach).
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buffer in
        if let base = buffer.baseAddress {
            _ = memset_s(base, buffer.count, 0, buffer.count)
        }
    }
}
