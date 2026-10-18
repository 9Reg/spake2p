use super::*;

const CTX: &[u8] = b"ffi test";
const IDP: &[u8] = b"client";
const IDV: &[u8] = b"server";

struct Keys {
    w0: [u8; 32],
    w1: [u8; 32],
    l: [u8; 65],
}

fn keys(seed: u8) -> Keys {
    let out = [seed; 80];
    let (mut w0, mut w1, mut l) = ([0u8; 32], [0u8; 32], [0u8; 65]);
    let rc = unsafe {
        spake2p_w0w1_from_pbkdf_output(out.as_ptr(), 80, w0.as_mut_ptr(), 32, w1.as_mut_ptr(), 32)
    };
    assert_eq!(rc, SPAKE2P_OK);
    let rc = unsafe { spake2p_register(w1.as_ptr(), 32, l.as_mut_ptr(), 65) };
    assert_eq!(rc, SPAKE2P_OK);
    Keys { w0, w1, l }
}

fn start(ctx: &[u8], k: &Keys) -> (*mut Spake2pProver, [u8; 65]) {
    let mut p = ptr::null_mut();
    let mut share_p = [0u8; 65];
    let rc = unsafe {
        spake2p_prover_start(
            ctx.as_ptr(),
            ctx.len(),
            IDP.as_ptr(),
            IDP.len(),
            IDV.as_ptr(),
            IDV.len(),
            k.w0.as_ptr(),
            32,
            k.w1.as_ptr(),
            32,
            &mut p,
            share_p.as_mut_ptr(),
            65,
        )
    };
    assert_eq!(rc, SPAKE2P_OK);
    assert!(!p.is_null());
    (p, share_p)
}

fn respond(
    ctx: &[u8],
    k: &Keys,
    share_p: &[u8],
) -> (Spake2pStatus, *mut Spake2pVerifier, [u8; 65], [u8; 32]) {
    let mut v = ptr::null_mut();
    let (mut sv, mut cv) = ([0u8; 65], [0u8; 32]);
    let rc = unsafe {
        spake2p_verifier_respond(
            ctx.as_ptr(),
            ctx.len(),
            IDP.as_ptr(),
            IDP.len(),
            IDV.as_ptr(),
            IDV.len(),
            k.w0.as_ptr(),
            32,
            k.l.as_ptr(),
            65,
            share_p.as_ptr(),
            share_p.len(),
            &mut v,
            sv.as_mut_ptr(),
            65,
            cv.as_mut_ptr(),
            32,
        )
    };
    (rc, v, sv, cv)
}

fn p_finish(p: *mut Spake2pProver, sv: &[u8], cv: &[u8]) -> (Spake2pStatus, [u8; 32], [u8; 32]) {
    let (mut cp, mut key) = ([0u8; 32], [0u8; 32]);
    let rc = unsafe {
        spake2p_prover_finish(
            p,
            sv.as_ptr(),
            sv.len(),
            cv.as_ptr(),
            cv.len(),
            cp.as_mut_ptr(),
            32,
            key.as_mut_ptr(),
            32,
        )
    };
    (rc, cp, key)
}

fn v_finish(v: *mut Spake2pVerifier, cp: &[u8]) -> (Spake2pStatus, [u8; 32]) {
    let mut key = [0u8; 32];
    let rc = unsafe { spake2p_verifier_finish(v, cp.as_ptr(), cp.len(), key.as_mut_ptr(), 32) };
    (rc, key)
}

#[test]
fn round_trip() {
    let k = keys(7);
    let (p, share_p) = start(CTX, &k);
    let (rc, v, sv, cv) = respond(CTX, &k, &share_p);
    assert_eq!(rc, SPAKE2P_OK);
    let (rc, cp, pkey) = p_finish(p, &sv, &cv);
    assert_eq!(rc, SPAKE2P_OK);
    let (rc, vkey) = v_finish(v, &cp);
    assert_eq!(rc, SPAKE2P_OK);
    assert_eq!(pkey, vkey);
    assert_ne!(pkey, [0u8; 32]);
}

#[test]
fn empty_context_with_null_pointer_is_accepted() {
    let k = keys(7);
    let mut p = ptr::null_mut();
    let mut share_p = [0u8; 65];
    let rc = unsafe {
        spake2p_prover_start(
            ptr::null(),
            0,
            IDP.as_ptr(),
            IDP.len(),
            IDV.as_ptr(),
            IDV.len(),
            k.w0.as_ptr(),
            32,
            k.w1.as_ptr(),
            32,
            &mut p,
            share_p.as_mut_ptr(),
            65,
        )
    };
    assert_eq!(rc, SPAKE2P_OK);
    unsafe { spake2p_prover_free(p) };
}

#[test]
fn wrong_password() {
    let (kp, kv) = (keys(7), keys(8));
    let (p, share_p) = start(CTX, &kp);
    let (rc, v, sv, cv) = respond(CTX, &kv, &share_p);
    assert_eq!(rc, SPAKE2P_OK);
    let (rc, cp, key) = p_finish(p, &sv, &cv);
    assert_eq!(rc, SPAKE2P_ERR_CONFIRMATION_FAILED);
    assert_eq!(
        (cp, key),
        ([0u8; 32], [0u8; 32]),
        "nothing written on failure"
    );
    unsafe { spake2p_verifier_free(v) };
}

#[test]
fn context_binding() {
    let k = keys(7);
    let (p, share_p) = start(b"one", &k);
    let (rc, v, sv, cv) = respond(b"two", &k, &share_p);
    assert_eq!(rc, SPAKE2P_OK);
    assert_eq!(p_finish(p, &sv, &cv).0, SPAKE2P_ERR_CONFIRMATION_FAILED);
    unsafe { spake2p_verifier_free(v) };
}

#[test]
fn tampered_confirmations_fail() {
    let k = keys(7);
    let (p, share_p) = start(CTX, &k);
    let (_, v, sv, mut cv) = respond(CTX, &k, &share_p);
    cv[0] ^= 1;
    let (rc, _, _) = p_finish(p, &sv, &cv);
    assert_eq!(rc, SPAKE2P_ERR_CONFIRMATION_FAILED);

    let (p, share_p) = start(CTX, &k);
    let (_, v2, sv, cv) = respond(CTX, &k, &share_p);
    let (rc, mut cp, _) = p_finish(p, &sv, &cv);
    assert_eq!(rc, SPAKE2P_OK);
    cp[31] ^= 0x80;
    assert_eq!(v_finish(v2, &cp).0, SPAKE2P_ERR_CONFIRMATION_FAILED);
    unsafe { spake2p_verifier_free(v) };
}

#[test]
fn invalid_shares() {
    let k = keys(7);
    let (p, share_p) = start(CTX, &k);
    let mut compressed = share_p;
    compressed[0] = 0x02;
    assert_eq!(
        respond(CTX, &k, &compressed).0,
        SPAKE2P_ERR_INVALID_ENCODING
    );
    assert_eq!(
        respond(CTX, &k, &share_p[..64]).0,
        SPAKE2P_ERR_INVALID_LENGTH
    );
    let mut off_curve = share_p;
    off_curve[64] ^= 1;
    assert_eq!(respond(CTX, &k, &off_curve).0, SPAKE2P_ERR_NOT_ON_CURVE);
    assert_eq!(respond(CTX, &k, &[0u8; 65]).0, SPAKE2P_ERR_INVALID_ENCODING);
    let (rc, v, _, _) = respond(CTX, &k, &share_p);
    assert_eq!(rc, SPAKE2P_OK);
    // Prover side: an invalid shareV is an error and still consumes the handle.
    assert_eq!(
        p_finish(p, &[0u8; 65], &[0u8; 32]).0,
        SPAKE2P_ERR_INVALID_ENCODING
    );
    unsafe { spake2p_verifier_free(v) };
}

#[test]
fn failed_respond_leaves_null_handle() {
    let k = keys(7);
    let (rc, v, sv, cv) = respond(CTX, &k, &[0u8; 65]);
    assert_ne!(rc, SPAKE2P_OK);
    assert!(v.is_null());
    assert_eq!((sv, cv), ([0u8; 65], [0u8; 32]));
}

#[test]
fn bad_scalars_and_lengths() {
    let mut l = [0u8; 65];
    let zero = [0u8; 32];
    let rc = unsafe { spake2p_register(zero.as_ptr(), 32, l.as_mut_ptr(), 65) };
    assert_eq!(rc, SPAKE2P_ERR_ZERO_SCALAR);
    let big = [0xffu8; 32];
    let rc = unsafe { spake2p_register(big.as_ptr(), 32, l.as_mut_ptr(), 65) };
    assert_eq!(rc, SPAKE2P_ERR_SCALAR_OUT_OF_RANGE);
    let rc = unsafe { spake2p_register(big.as_ptr(), 31, l.as_mut_ptr(), 65) };
    assert_eq!(rc, SPAKE2P_ERR_INVALID_LENGTH);

    let (mut w0, mut w1) = ([0u8; 32], [0u8; 32]);
    for n in [0usize, 79, 81] {
        let out = [1u8; 81];
        let rc = unsafe {
            spake2p_w0w1_from_pbkdf_output(
                out.as_ptr(),
                n,
                w0.as_mut_ptr(),
                32,
                w1.as_mut_ptr(),
                32,
            )
        };
        assert_eq!(rc, SPAKE2P_ERR_INVALID_LENGTH, "len {n}");
    }
}

#[test]
fn null_pointers() {
    let k = keys(7);
    let mut buf = [0u8; 80];
    unsafe {
        assert_eq!(
            spake2p_w0w1_from_pbkdf_output(
                ptr::null(),
                80,
                buf.as_mut_ptr(),
                32,
                buf.as_mut_ptr(),
                32
            ),
            SPAKE2P_ERR_NULL_POINTER
        );
        assert_eq!(
            spake2p_w0w1_from_pbkdf_output(
                buf.as_ptr(),
                80,
                ptr::null_mut(),
                32,
                buf.as_mut_ptr(),
                32
            ),
            SPAKE2P_ERR_NULL_POINTER
        );
        assert_eq!(
            spake2p_register(ptr::null(), 32, buf.as_mut_ptr(), 65),
            SPAKE2P_ERR_NULL_POINTER
        );
        assert_eq!(
            spake2p_prover_start(
                ptr::null(),
                3,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                0
            ),
            SPAKE2P_ERR_NULL_POINTER
        );
        assert_eq!(
            spake2p_prover_finish(
                ptr::null_mut(),
                buf.as_ptr(),
                65,
                buf.as_ptr(),
                32,
                buf.as_mut_ptr(),
                32,
                buf.as_mut_ptr(),
                32
            ),
            SPAKE2P_ERR_NULL_POINTER
        );
        assert_eq!(
            spake2p_verifier_finish(ptr::null_mut(), buf.as_ptr(), 32, buf.as_mut_ptr(), 32),
            SPAKE2P_ERR_NULL_POINTER
        );
        spake2p_prover_free(ptr::null_mut());
        spake2p_verifier_free(ptr::null_mut());
    }
    // NULL output buffer / NULL input with non-zero length, with a live handle: still consumed.
    let (p, _) = start(CTX, &k);
    let rc = unsafe {
        spake2p_prover_finish(
            p,
            ptr::null(),
            65,
            buf.as_ptr(),
            32,
            buf.as_mut_ptr(),
            32,
            buf.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_NULL_POINTER);
    let mut pp = ptr::null_mut();
    let rc = unsafe {
        spake2p_prover_start(
            CTX.as_ptr(),
            CTX.len(),
            IDP.as_ptr(),
            IDP.len(),
            IDV.as_ptr(),
            IDV.len(),
            k.w0.as_ptr(),
            32,
            k.w1.as_ptr(),
            32,
            &mut pp,
            ptr::null_mut(),
            65,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_NULL_POINTER);
    assert!(pp.is_null());
}

#[test]
fn short_output_buffers() {
    let k = keys(7);
    let mut p = ptr::null_mut();
    let mut share_p = [0u8; 65];
    let rc = unsafe {
        spake2p_prover_start(
            CTX.as_ptr(),
            CTX.len(),
            IDP.as_ptr(),
            IDP.len(),
            IDV.as_ptr(),
            IDV.len(),
            k.w0.as_ptr(),
            32,
            k.w1.as_ptr(),
            32,
            &mut p,
            share_p.as_mut_ptr(),
            64,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_BUFFER_TOO_SMALL);
    assert!(p.is_null());
    assert_eq!(share_p, [0u8; 65]);

    let (p, share_p) = start(CTX, &k);
    let (_, v, sv, cv) = respond(CTX, &k, &share_p);
    let mut small = [0u8; 31];
    let mut key = [0u8; 32];
    let rc = unsafe {
        spake2p_prover_finish(
            p,
            sv.as_ptr(),
            65,
            cv.as_ptr(),
            32,
            small.as_mut_ptr(),
            31,
            key.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_BUFFER_TOO_SMALL);
    assert_eq!((small, key), ([0u8; 31], [0u8; 32]));
    unsafe { spake2p_verifier_free(v) };

    let mut w = [0u8; 32];
    let pb = [3u8; 80];
    let rc = unsafe {
        spake2p_w0w1_from_pbkdf_output(pb.as_ptr(), 80, w.as_mut_ptr(), 31, w.as_mut_ptr(), 32)
    };
    assert_eq!(rc, SPAKE2P_ERR_BUFFER_TOO_SMALL);
}

#[test]
fn finish_failure_does_not_poison_a_fresh_exchange() {
    // The allocator test (tests/handle_free.rs) proves a failed finish frees the handle. Here: a
    // finish that failed leaves no state behind, and the same inputs on a fresh handle succeed.
    let k = keys(7);
    let (p, share_p) = start(CTX, &k);
    let (_, v, sv, cv) = respond(CTX, &k, &share_p);
    assert_eq!(p_finish(p, &sv[..64], &cv).0, SPAKE2P_ERR_INVALID_LENGTH);
    unsafe { spake2p_verifier_free(v) };

    let (p, share_p) = start(CTX, &k);
    let (rc, v, sv, cv) = respond(CTX, &k, &share_p);
    assert_eq!(rc, SPAKE2P_OK);
    let (rc, cp, pkey) = p_finish(p, &sv, &cv);
    assert_eq!(rc, SPAKE2P_OK);
    let (rc, vkey) = v_finish(v, &cp);
    assert_eq!(rc, SPAKE2P_OK);
    assert_eq!(pkey, vkey);
}

#[test]
fn pbkdf_input_matches_core() {
    let (pw, a, b) = (b"123456".as_slice(), b"c".as_slice(), b"s".as_slice());
    let want = spake2p::pbkdf_input(pw, a, b);
    let mut n = 0usize;
    let mut probe = [0u8; 1];
    let rc = unsafe {
        spake2p_pbkdf_input(
            pw.as_ptr(),
            pw.len(),
            a.as_ptr(),
            a.len(),
            b.as_ptr(),
            b.len(),
            probe.as_mut_ptr(),
            0,
            &mut n,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_BUFFER_TOO_SMALL);
    assert_eq!(n, want.len());
    let mut out = vec![0u8; n];
    let rc = unsafe {
        spake2p_pbkdf_input(
            pw.as_ptr(),
            pw.len(),
            a.as_ptr(),
            a.len(),
            b.as_ptr(),
            b.len(),
            out.as_mut_ptr(),
            n,
            &mut n,
        )
    };
    assert_eq!(rc, SPAKE2P_OK);
    assert_eq!(out, *want);
}

#[test]
fn guard_turns_a_panic_into_a_status() {
    // `guard` wraps every exported body; no exported function can be made to panic from outside.
    assert_eq!(guard(|| panic!("boom")), SPAKE2P_ERR_PANIC);
}

#[test]
fn bad_stored_l_is_invalid_record_not_a_peer_error() {
    let k = keys(7);
    let (p, share_p) = start(CTX, &k);
    let mut bad_l = Keys {
        w0: k.w0,
        w1: k.w1,
        l: k.l,
    };
    for mutate in 0..4 {
        bad_l.l = k.l;
        match mutate {
            0 => bad_l.l[64] ^= 1,    // off curve
            1 => bad_l.l[0] = 0x02,   // not uncompressed
            2 => bad_l.l = [0u8; 65], // zero
            _ => bad_l.l[1] ^= 0x80,  // another coordinate
        }
        let (rc, v, _, _) = respond(CTX, &bad_l, &share_p);
        assert_eq!(rc, SPAKE2P_ERR_INVALID_RECORD, "mutation {mutate}");
        assert!(v.is_null());
    }
    assert_eq!(SPAKE2P_ERR_INVALID_RECORD, 10);
    assert_eq!(SPAKE2P_ERR_UNKNOWN, 9);
    assert_eq!(SPAKE2P_ERR_NULL_POINTER, 100);
    unsafe { spake2p_prover_free(p) };
}

#[test]
fn l_validate_accepts_a_good_l_and_rejects_every_defect() {
    let k = keys(7);
    let v = |b: &[u8]| unsafe { spake2p_l_validate(b.as_ptr(), b.len()) };
    assert_eq!(v(&k.l), SPAKE2P_OK);
    let mut bad = k.l;
    bad[64] ^= 1;
    assert_eq!(v(&bad), SPAKE2P_ERR_INVALID_RECORD);
    bad = k.l;
    bad[0] = 0x02;
    assert_eq!(v(&bad), SPAKE2P_ERR_INVALID_RECORD);
    assert_eq!(v(&[0u8; 65]), SPAKE2P_ERR_INVALID_RECORD);
    assert_eq!(v(&k.l[..64]), SPAKE2P_ERR_INVALID_RECORD);
    assert_eq!(v(&[]), SPAKE2P_ERR_INVALID_RECORD);
    assert_eq!(
        unsafe { spake2p_l_validate(ptr::null(), 0) },
        SPAKE2P_ERR_INVALID_RECORD
    );
    assert_eq!(
        unsafe { spake2p_l_validate(ptr::null(), 65) },
        SPAKE2P_ERR_NULL_POINTER
    );
}

#[test]
fn abi_version_is_one() {
    assert_eq!(spake2p_abi_version(), 1);
    assert!(include_str!("../include/spake2p.h").contains("#define SPAKE2P_ABI_VERSION 1u"));
}

#[test]
fn pbkdf_input_probe_accepts_null_out_with_zero_capacity() {
    let mut n = 0usize;
    let rc = unsafe {
        spake2p_pbkdf_input(
            b"pw".as_ptr(),
            2,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut n,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_BUFFER_TOO_SMALL);
    assert_eq!(n, 24 + 2);
    // NULL out with a non-zero capacity is still a NULL pointer error.
    let rc = unsafe {
        spake2p_pbkdf_input(
            b"pw".as_ptr(),
            2,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            64,
            &mut n,
        )
    };
    assert_eq!(rc, SPAKE2P_ERR_NULL_POINTER);
}

/// `NAME = value` pairs from a source text for names starting with `prefix`.
fn constants(text: &str, prefix: &str) -> std::collections::BTreeMap<String, i64> {
    let mut m = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("pub const ").unwrap_or(line);
        if !line.starts_with(prefix) {
            continue;
        }
        let name_end = line
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap();
        let name = &line[..name_end];
        let rest = line[name_end..].trim_start_matches(|c: char| c != '=');
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let digits: String = rest
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(v) = digits.parse() {
            m.insert(name.to_string(), v);
        }
    }
    m
}

#[test]
fn status_constants_match_the_header() {
    let header = constants(include_str!("../include/spake2p.h"), "SPAKE2P_ERR_");
    let source = constants(include_str!("lib.rs"), "SPAKE2P_ERR_");
    let table: [(&str, Spake2pStatus); 13] = [
        ("SPAKE2P_ERR_INVALID_LENGTH", SPAKE2P_ERR_INVALID_LENGTH),
        ("SPAKE2P_ERR_INVALID_ENCODING", SPAKE2P_ERR_INVALID_ENCODING),
        ("SPAKE2P_ERR_NOT_ON_CURVE", SPAKE2P_ERR_NOT_ON_CURVE),
        ("SPAKE2P_ERR_IDENTITY_POINT", SPAKE2P_ERR_IDENTITY_POINT),
        (
            "SPAKE2P_ERR_SCALAR_OUT_OF_RANGE",
            SPAKE2P_ERR_SCALAR_OUT_OF_RANGE,
        ),
        ("SPAKE2P_ERR_ZERO_SCALAR", SPAKE2P_ERR_ZERO_SCALAR),
        (
            "SPAKE2P_ERR_CONFIRMATION_FAILED",
            SPAKE2P_ERR_CONFIRMATION_FAILED,
        ),
        ("SPAKE2P_ERR_RNG", SPAKE2P_ERR_RNG),
        ("SPAKE2P_ERR_UNKNOWN", SPAKE2P_ERR_UNKNOWN),
        ("SPAKE2P_ERR_INVALID_RECORD", SPAKE2P_ERR_INVALID_RECORD),
        ("SPAKE2P_ERR_NULL_POINTER", SPAKE2P_ERR_NULL_POINTER),
        ("SPAKE2P_ERR_BUFFER_TOO_SMALL", SPAKE2P_ERR_BUFFER_TOO_SMALL),
        ("SPAKE2P_ERR_PANIC", SPAKE2P_ERR_PANIC),
    ];
    // The table is the real values; the parsed lib.rs text must agree with it, and the header with both.
    assert_eq!(
        source.len(),
        table.len(),
        "lib.rs defines a status the table lacks: {source:?}"
    );
    assert_eq!(
        header.len(),
        table.len(),
        "header and table differ: {header:?}"
    );
    for (name, value) in table {
        assert_eq!(header.get(name), Some(&(value as i64)), "{name} in header");
        assert_eq!(source.get(name), Some(&(value as i64)), "{name} in lib.rs");
    }
    assert_eq!(
        constants(include_str!("../include/spake2p.h"), "SPAKE2P_OK").get("SPAKE2P_OK"),
        Some(&0)
    );
    assert_eq!(SPAKE2P_OK, 0);
}

#[test]
fn length_constants_match_the_header() {
    let h = constants(include_str!("../include/spake2p.h"), "SPAKE2P_");
    for (name, want) in [
        ("SPAKE2P_SCALAR_LEN", SCALAR_LEN),
        ("SPAKE2P_POINT_LEN", POINT_LEN),
        ("SPAKE2P_CONFIRM_LEN", SCALAR_LEN),
        ("SPAKE2P_KEY_LEN", SCALAR_LEN),
        ("SPAKE2P_PBKDF_OUTPUT_LEN", PBKDF_OUTPUT_LEN),
    ] {
        assert_eq!(h.get(name), Some(&(want as i64)), "{name}");
    }
}
