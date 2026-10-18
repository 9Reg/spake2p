// Cross-language interop driver (SPEC.md "Driver contract").
//
// Usage: spake2p-interop-driver prover|verifier <config.json>
//
// Peer messages are one JSON object per line on stdout/stdin; the outcome is one JSON line on
// stderr. Exit code 0 on success, 1 on protocol failure, 2 on bad usage.

import CryptoKit
import Foundation
import Spake2p

struct Failure: Error { let kind: String }

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func unhex(_ s: String) -> Data? {
    let u = Array(s.utf8)
    guard u.count % 2 == 0 else { return nil }
    var out = Data(capacity: u.count / 2)
    for i in stride(from: 0, to: u.count, by: 2) {
        guard let b = UInt8(String(decoding: u[i..<i + 2], as: UTF8.self), radix: 16),
            u[i] != 0x2b, u[i] != 0x2d  // reject a sign Swift's radix parser would accept
        else { return nil }
        out.append(b)
    }
    return out
}

func kind(_ e: Spake2pError) -> String {
    switch e {
    case .invalidLength: "invalid_message"
    case .invalidEncoding, .notOnCurve, .identityPoint: "invalid_point"
    case .invalidRecord: "invalid_record"
    case .scalarOutOfRange, .zeroScalar: "invalid_scalar"
    case .confirmationFailed: "confirmation_failed"
    case .rng: "random"
    case .alreadyFinished: "finished"
    case .unexpected: "io"
    }
}

func report(_ line: String, exit code: Int32) -> Never {
    FileHandle.standardError.write(Data((line + "\n").utf8))
    exit(code)
}

func send(_ fields: [(String, Any)]) {
    // Keys in the order given; values are strings or true.
    let body = fields.map { k, v in
        if let s = v as? String { return "\"\(k)\":\"\(s)\"" }
        return "\"\(k)\":true"
    }.joined(separator: ",")
    FileHandle.standardOutput.write(Data(("{" + body + "}\n").utf8))
}

func recv() throws -> [String: Any] {
    guard let line = readLine(strippingNewline: true) else { throw Failure(kind: "io") }
    guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
        throw Failure(kind: "io")
    }
    return obj
}

func hexField(_ m: [String: Any], _ key: String) throws -> Data {
    guard let s = m[key] as? String, let d = unhex(s) else { throw Failure(kind: "io") }
    return d
}

struct Config {
    let context, idProver, idVerifier, pbkdfOutput: Data
}

func loadConfig(_ path: String) -> Config? {
    guard let data = FileManager.default.contents(atPath: path),
        let v = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return nil }
    func f(_ k: String) -> Data? { (v[k] as? String).flatMap(unhex) }
    guard let c = f("context"), let p = f("idProver"), let s = f("idVerifier"), let o = f("pbkdf_output")
    else { return nil }
    return Config(context: c, idProver: p, idVerifier: s, pbkdfOutput: o)
}

func runProver(_ cfg: Config) throws -> Data {
    do {
        let (w0, w1) = try Spake2p.w0w1(fromPBKDFOutput: cfg.pbkdfOutput)
        let (prover, shareP) = try Prover.start(
            context: cfg.context, idProver: cfg.idProver, idVerifier: cfg.idVerifier, w0: w0, w1: w1)
        send([("shareP", hex(shareP.bytes))])
        let msg = try recv()
        if msg["abort"] as? Bool == true { throw Failure(kind: "peer_aborted") }
        let shareV = try hexField(msg, "shareV"), confirmV = try hexField(msg, "confirmV")
        guard shareV.count == 65 else { throw Failure(kind: "invalid_point") }
        do {
            let (confirmP, key) = try prover.finish(shareV: ShareV(shareV), confirmV: ConfirmV(confirmV))
            send([("confirmP", hex(confirmP.bytes))])
            return key.withUnsafeBytes { Data($0) }
        } catch {
            send([("abort", true)])
            throw error
        }
    } catch let e as Spake2pError {
        throw Failure(kind: kind(e))
    }
}

func runVerifier(_ cfg: Config) throws -> Data {
    do {
        // Derive w0 and L, then let w1 go: the Verifier never keeps it.
        let (w0, l): (W0, L) = try {
            let (w0, w1) = try Spake2p.w0w1(fromPBKDFOutput: cfg.pbkdfOutput)
            return (w0, try Spake2p.register(w1: w1))
        }()
        let first = try recv()
        if first["abort"] as? Bool == true { throw Failure(kind: "peer_aborted") }
        let shareP = try hexField(first, "shareP")
        guard shareP.count == 65 else { throw Failure(kind: "invalid_point") }
        let (verifier, shareV, confirmV) = try Verifier.respond(
            context: cfg.context, idProver: cfg.idProver, idVerifier: cfg.idVerifier,
            w0: w0, l: l, shareP: ShareP(shareP))
        send([("shareV", hex(shareV.bytes)), ("confirmV", hex(confirmV.bytes))])
        let msg = try recv()
        if msg["abort"] as? Bool == true { throw Failure(kind: "peer_aborted") }
        let key = try verifier.finish(confirmP: ConfirmP(hexField(msg, "confirmP")))
        return key.withUnsafeBytes { Data($0) }
    } catch let e as Spake2pError {
        throw Failure(kind: kind(e))
    }
}

let args = CommandLine.arguments
guard args.count == 3, let cfg = loadConfig(args[2]) else {
    report("usage: spake2p-interop-driver prover|verifier <config.json>", exit: 2)
}
let role = args[1]
guard role == "prover" || role == "verifier" else {
    report("usage: spake2p-interop-driver prover|verifier <config.json>", exit: 2)
}
do {
    let key = try role == "prover" ? runProver(cfg) : runVerifier(cfg)
    report("{\"ok\": true, \"K_shared\": \"\(hex(key))\"}", exit: 0)
} catch let f as Failure {
    report("{\"ok\": false, \"error\": \"\(f.kind)\"}", exit: 1)
} catch {
    report("{\"ok\": false, \"error\": \"io\"}", exit: 1)
}
