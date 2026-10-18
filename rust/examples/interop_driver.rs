//! Cross-language interop driver (SPEC.md "Driver contract").
//!
//! Usage: `interop_driver prover|verifier <config.json>`
//!
//! Peer messages are one JSON object per line on stdout/stdin; the outcome is one JSON line on
//! stderr. Exit code 0 on success, 1 on protocol failure, 2 on bad usage.

use std::io::{self, BufRead, Write};
use std::process::exit;

use serde_json::{json, Value};
use spake2p::{
    register, w0w1_from_pbkdf_output, ConfirmP, ConfirmV, Error, Prover, ShareP, ShareV, Verifier,
    L,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn usage() -> ! {
    eprintln!("usage: interop_driver prover|verifier <config.json>");
    exit(2)
}

/// Reports the outcome on stderr and exits.
fn finish(result: Result<[u8; 32], String>) -> ! {
    match result {
        Ok(key) => {
            eprintln!("{}", json!({"ok": true, "K_shared": hex(&key)}));
            exit(0)
        }
        Err(kind) => {
            eprintln!("{}", json!({"ok": false, "error": kind}));
            exit(1)
        }
    }
}

fn kind(e: &Error) -> String {
    match e {
        Error::InvalidLength => "invalid_length",
        Error::InvalidEncoding => "invalid_encoding",
        Error::NotOnCurve => "not_on_curve",
        Error::IdentityPoint => "identity_point",
        Error::ScalarOutOfRange => "scalar_out_of_range",
        Error::ZeroScalar => "zero_scalar",
        Error::ConfirmationFailed => "confirmation_failed",
        Error::Rng => "rng",
        _ => "error",
    }
    .to_string()
}

fn send(out: &mut impl Write, v: Value) {
    writeln!(out, "{v}")
        .and_then(|_| out.flush())
        .unwrap_or_else(|_| exit(1));
}

fn recv(input: &mut impl BufRead) -> Result<Value, String> {
    let mut line = String::new();
    match input.read_line(&mut line) {
        Ok(0) | Err(_) => Err("peer_closed".into()),
        Ok(_) => serde_json::from_str(&line).map_err(|_| "bad_message".to_string()),
    }
}

fn hex_field(v: &Value, key: &str) -> Result<Vec<u8>, String> {
    v.get(key)
        .and_then(Value::as_str)
        .and_then(unhex)
        .ok_or_else(|| "bad_message".to_string())
}

struct Config {
    context: Vec<u8>,
    id_prover: Vec<u8>,
    id_verifier: Vec<u8>,
    pbkdf_output: Vec<u8>,
}

fn load_config(path: &str) -> Option<Config> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let f = |k: &str| v.get(k).and_then(Value::as_str).and_then(unhex);
    Some(Config {
        context: f("context")?,
        id_prover: f("idProver")?,
        id_verifier: f("idVerifier")?,
        pbkdf_output: f("pbkdf_output")?,
    })
}

fn run_prover(cfg: Config) -> Result<[u8; 32], String> {
    let (w0, w1) = w0w1_from_pbkdf_output(&cfg.pbkdf_output).map_err(|e| kind(&e))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut out = io::stdout().lock();

    let (prover, share_p) = Prover::start(&cfg.context, &cfg.id_prover, &cfg.id_verifier, &w0, &w1)
        .map_err(|e| kind(&e))?;
    send(&mut out, json!({"shareP": hex(share_p.as_bytes())}));

    let msg = recv(&mut input)?;
    let share_v = ShareV::from_bytes(&hex_field(&msg, "shareV")?).map_err(|e| kind(&e))?;
    let confirm_v = ConfirmV::from_bytes(&hex_field(&msg, "confirmV")?).map_err(|e| kind(&e))?;
    match prover.finish(&share_v, &confirm_v) {
        Ok((confirm_p, key)) => {
            send(&mut out, json!({"confirmP": hex(confirm_p.as_bytes())}));
            Ok(*key.as_bytes())
        }
        Err(e) => {
            send(&mut out, json!({"abort": true}));
            Err(kind(&e))
        }
    }
}

fn run_verifier(cfg: Config) -> Result<[u8; 32], String> {
    // Derive w0 and L, then drop w1: the Verifier never keeps it.
    let (w0, l): (_, L) = {
        let (w0, w1) = w0w1_from_pbkdf_output(&cfg.pbkdf_output).map_err(|e| kind(&e))?;
        let l = register(&w1);
        (w0, l)
    };
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut out = io::stdout().lock();

    let msg = recv(&mut input)?;
    let share_p = ShareP::from_bytes(&hex_field(&msg, "shareP")?).map_err(|e| kind(&e))?;
    let (verifier, share_v, confirm_v) = Verifier::respond(
        &cfg.context,
        &cfg.id_prover,
        &cfg.id_verifier,
        &w0,
        &l,
        &share_p,
    )
    .map_err(|e| kind(&e))?;
    send(
        &mut out,
        json!({"shareV": hex(share_v.as_bytes()), "confirmV": hex(confirm_v.as_bytes())}),
    );

    let msg = recv(&mut input)?;
    if msg.get("abort").and_then(Value::as_bool) == Some(true) {
        return Err("peer_aborted".into());
    }
    let confirm_p = ConfirmP::from_bytes(&hex_field(&msg, "confirmP")?).map_err(|e| kind(&e))?;
    let key = verifier.finish(&confirm_p).map_err(|e| kind(&e))?;
    Ok(*key.as_bytes())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        usage();
    }
    let Some(cfg) = load_config(&args[2]) else {
        usage()
    };
    match args[1].as_str() {
        "prover" => finish(run_prover(cfg)),
        "verifier" => finish(run_verifier(cfg)),
        _ => usage(),
    }
}
