import CSpake2p
import CryptoKit
import Foundation

// Typed values for everything that crosses the API. Each validating init checks what can be checked
// without the curve (lengths); `L` is checked fully by the Rust core. Point checks on shares happen
// when the exchange uses them, where the error belongs to the peer.

/// A secret scalar held in a `SymmetricKey` (zeroised by CryptoKit when released). No `description`,
/// no `Equatable`: it cannot be printed or compared by accident.
public struct W0: Sendable {
    private let key: SymmetricKey

    /// - Throws: ``Spake2pError/invalidLength`` unless `data` is 32 bytes. Range and zero are checked
    ///   when the scalar is used. Wipe your own copy of `data` afterwards if you hold one.
    public init(_ data: Data) throws(Spake2pError) {
        guard data.count == Spake2p.scalarLength else { throw .invalidLength }
        key = SymmetricKey(data: data)
    }

    init(wiping bytes: inout [UInt8]) { key = SymmetricKey(data: bytes); wipe(&bytes) }

    /// Calls `body` with the 32 bytes (to store `w0` next to `L`). The buffer is valid only inside it.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try key.withUnsafeBytes(body)
    }
}

/// A secret scalar `w1` (the Prover's; a Verifier never keeps it). Same handling as ``W0``.
public struct W1: Sendable {
    private let key: SymmetricKey

    /// - Throws: ``Spake2pError/invalidLength`` unless `data` is 32 bytes.
    public init(_ data: Data) throws(Spake2pError) {
        guard data.count == Spake2p.scalarLength else { throw .invalidLength }
        key = SymmetricKey(data: data)
    }

    init(wiping bytes: inout [UInt8]) { key = SymmetricKey(data: bytes); wipe(&bytes) }

    /// Calls `body` with the 32 bytes. The buffer is valid only inside it.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try key.withUnsafeBytes(body)
    }
}

/// The Verifier's registration point `L = w1·P`: 65 bytes, uncompressed SEC1, on the curve, not the
/// identity. Not secret, but it is a stored record: a bad one is a local fault.
public struct L: Sendable, Equatable {
    public let bytes: Data

    /// - Throws: ``Spake2pError/invalidRecord`` for any defect, wrong length included (checked by
    ///   the Rust core's `L::parse`).
    public init(_ data: Data) throws(Spake2pError) {
        _ = Spake2p.abiChecked
        let b = [UInt8](data)
        guard Int(spake2p_l_validate(b, b.count)) == SPAKE2P_OK else { throw .invalidRecord }
        bytes = data
    }
}

/// Declares a public, length-checked, non-secret wire value.
private func checkedLength(_ data: Data, _ n: Int) throws(Spake2pError) {
    guard data.count == n else { throw .invalidLength }
}

/// The Prover's share (65 bytes, uncompressed SEC1).
public struct ShareP: Sendable, Equatable {
    public let bytes: Data
    /// - Throws: ``Spake2pError/invalidLength`` unless 65 bytes. The point itself is checked when used.
    public init(_ data: Data) throws(Spake2pError) {
        try checkedLength(data, Spake2p.pointLength)
        bytes = data
    }
}

/// The Verifier's share (65 bytes, uncompressed SEC1).
public struct ShareV: Sendable, Equatable {
    public let bytes: Data
    /// - Throws: ``Spake2pError/invalidLength`` unless 65 bytes. The point itself is checked when used.
    public init(_ data: Data) throws(Spake2pError) {
        try checkedLength(data, Spake2p.pointLength)
        bytes = data
    }
}

/// The Prover's confirmation tag (32 bytes).
public struct ConfirmP: Sendable, Equatable {
    public let bytes: Data
    /// - Throws: ``Spake2pError/invalidLength`` unless 32 bytes.
    public init(_ data: Data) throws(Spake2pError) {
        try checkedLength(data, Spake2p.confirmLength)
        bytes = data
    }
}

/// The Verifier's confirmation tag (32 bytes).
public struct ConfirmV: Sendable, Equatable {
    public let bytes: Data
    /// - Throws: ``Spake2pError/invalidLength`` unless 32 bytes.
    public init(_ data: Data) throws(Spake2pError) {
        try checkedLength(data, Spake2p.confirmLength)
        bytes = data
    }
}
