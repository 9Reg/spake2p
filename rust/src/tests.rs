//! The seven test groups of SPEC.md.

use super::*;
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().unwrap()
}

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/rfc9383-p256-sha256-hkdf-hmac.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn field(v: &Value, k: &str) -> Vec<u8> {
    unhex(v[k].as_str().unwrap())
}

const CTX: &[u8] = b"test context";
const IDP: &[u8] = b"client";
const IDV: &[u8] = b"server";

/// w0, w1, L from a fixed pbkdf output; `seed` varies the password.
fn creds(seed: u8) -> (W0, W1, L) {
    let (w0, w1) = w0w1_from_pbkdf_output(&[seed; 80]).unwrap();
    let l = register(&w1).unwrap();
    (w0, w1, l)
}

/// Runs a full exchange; returns the Prover's and the Verifier's results.
fn run(
    prover_seed: u8,
    verifier_seed: u8,
    pctx: (&[u8], &[u8], &[u8]),
    vctx: (&[u8], &[u8], &[u8]),
) -> (Result<SharedKey>, Result<SharedKey>) {
    let (pw0, pw1, _) = creds(prover_seed);
    let (vw0, _, vl) = creds(verifier_seed);
    let (prover, share_p) = Prover::start(pctx.0, pctx.1, pctx.2, &pw0, &pw1).unwrap();
    let (verifier, share_v, confirm_v) =
        Verifier::respond(vctx.0, vctx.1, vctx.2, &vw0, &vl, &share_p).unwrap();
    match prover.finish(&share_v, &confirm_v) {
        Ok((confirm_p, kp)) => (Ok(kp), verifier.finish(&confirm_p)),
        Err(e) => (Err(e), Err(Error::ConfirmationFailed)),
    }
}

// 1. RFC vector ----------------------------------------------------------------------------

#[test]
fn rfc_vector() {
    let v = vectors();
    let w0 = W0::from_bytes(&field(&v, "w0")).unwrap();
    let w1 = W1::from_bytes(&field(&v, "w1")).unwrap();
    let (ctx, idp, idv) = (
        v["context"].as_str().unwrap().as_bytes(),
        b"client".as_slice(),
        b"server".as_slice(),
    );
    assert_eq!(v["idProver"].as_str().unwrap().as_bytes(), idp);
    assert_eq!(v["idVerifier"].as_str().unwrap().as_bytes(), idv);

    let l = register(&w1).unwrap();
    assert_eq!(hex(l.as_bytes()), v["L"].as_str().unwrap());

    let (prover, share_p) =
        Prover::start_with_scalar(ctx, idp, idv, &w0, &w1, &arr(&field(&v, "x")));
    assert_eq!(hex(share_p.as_bytes()), v["shareP"].as_str().unwrap());

    let (verifier, share_v, confirm_v, d) =
        Verifier::respond_with_scalar(ctx, idp, idv, &w0, &l, &share_p, &arr(&field(&v, "y")))
            .unwrap();
    assert_eq!(hex(share_v.as_bytes()), v["shareV"].as_str().unwrap());
    assert_eq!(hex(confirm_v.as_bytes()), v["confirmV"].as_str().unwrap());
    for (name, got) in [
        ("Z", &d.z[..]),
        ("V", &d.v[..]),
        ("TT", &d.tt[..]),
        ("K_main", &d.k_main[..]),
        ("K_confirmP", &d.k_confirm_p[..]),
        ("K_confirmV", &d.k_confirm_v[..]),
        ("K_shared", &d.k_shared[..]),
    ] {
        assert_eq!(
            hex(got),
            v[name].as_str().unwrap(),
            "{name} (verifier side)"
        );
    }

    // The Prover derives the same values from its own side.
    let dp = prover.derived_for_test(&share_v);
    assert_eq!(dp.tt, d.tt);
    assert_eq!(dp.z, d.z);
    assert_eq!(dp.v, d.v);
    assert_eq!(dp.k_shared, d.k_shared);

    let (confirm_p, key_p) = prover.finish(&share_v, &confirm_v).unwrap();
    assert_eq!(hex(confirm_p.as_bytes()), v["confirmP"].as_str().unwrap());
    assert_eq!(hex(key_p.as_bytes()), v["K_shared"].as_str().unwrap());
    let key_v = verifier.finish(&confirm_p).unwrap();
    assert_eq!(key_v.as_bytes(), key_p.as_bytes());
}

#[test]
fn constants_m_and_n_match_the_rfc_transcript() {
    // The vector's TT embeds M and N uncompressed; check ours match, independent of the flow.
    let v = vectors();
    let tt = hex(&field(&v, "TT"));
    assert!(tt.contains(&hex(&encode_point(&constant_point(&M_COMPRESSED)).unwrap())));
    assert!(tt.contains(&hex(&encode_point(&constant_point(&N_COMPRESSED)).unwrap())));
}

// 2. Round trip ----------------------------------------------------------------------------

#[test]
fn round_trip() {
    let (kp, kv) = run(7, 7, (CTX, IDP, IDV), (CTX, IDP, IDV));
    assert_eq!(kp.unwrap().as_bytes(), kv.unwrap().as_bytes());
}

#[test]
fn round_trip_empty_context_and_identities() {
    let (kp, kv) = run(7, 7, (b"", b"", b""), (b"", b"", b""));
    assert_eq!(kp.unwrap().as_bytes(), kv.unwrap().as_bytes());
}

#[test]
fn sessions_get_different_keys() {
    let a = run(7, 7, (CTX, IDP, IDV), (CTX, IDP, IDV)).0.unwrap();
    let b = run(7, 7, (CTX, IDP, IDV), (CTX, IDP, IDV)).0.unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

// 3. Wrong password ------------------------------------------------------------------------

#[test]
fn wrong_password_fails_on_confirm_v() {
    let (kp, _) = run(1, 2, (CTX, IDP, IDV), (CTX, IDP, IDV));
    assert_eq!(kp.unwrap_err(), Error::ConfirmationFailed);
}

#[test]
fn wrong_w1_only_fails() {
    // Right w0 but a w1 that does not match L.
    let (w0, _, l) = creds(3);
    let (_, w1_other, _) = creds(4);
    let (prover, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1_other).unwrap();
    let (_, share_v, confirm_v) = Verifier::respond(CTX, IDP, IDV, &w0, &l, &share_p).unwrap();
    assert_eq!(
        prover.finish(&share_v, &confirm_v).unwrap_err(),
        Error::ConfirmationFailed
    );
}

// 4. Tampering -----------------------------------------------------------------------------

struct Session {
    prover: Prover,
    verifier: Verifier,
    share_p: ShareP,
    share_v: ShareV,
    confirm_v: ConfirmV,
}

fn session() -> Session {
    let (w0, w1, l) = creds(9);
    let (prover, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let (verifier, share_v, confirm_v) =
        Verifier::respond(CTX, IDP, IDV, &w0, &l, &share_p).unwrap();
    Session {
        prover,
        verifier,
        share_p,
        share_v,
        confirm_v,
    }
}

#[test]
fn tampered_share_p_fails() {
    let (w0, _, l) = creds(9);
    let s = session();
    // Flipping a bit of a coordinate gives an off-curve point, so the Verifier refuses it.
    let mut bytes = *s.share_p.as_bytes();
    bytes[10] ^= 0x01;
    let r = Verifier::respond(CTX, IDP, IDV, &w0, &l, &ShareP::from(bytes));
    assert!(r.is_err());
}

#[test]
fn tampered_share_p_valid_point_fails_confirmation() {
    // A different valid point in place of shareP: the Verifier accepts it, but the Prover's
    // confirmation check (over its own shareP) must fail.
    let (w0, w1, l) = creds(9);
    let (prover, _real) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let (_other, other_share) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let (_v, share_v, confirm_v) = Verifier::respond(CTX, IDP, IDV, &w0, &l, &other_share).unwrap();
    assert_eq!(
        prover.finish(&share_v, &confirm_v).unwrap_err(),
        Error::ConfirmationFailed
    );
}

#[test]
fn tampered_share_v_fails() {
    let s = session();
    let mut bytes = *s.share_v.as_bytes();
    bytes[10] ^= 0x01;
    assert!(s.prover.finish(&ShareV::from(bytes), &s.confirm_v).is_err());
}

#[test]
fn valid_but_wrong_share_v_fails_confirmation() {
    let s = session();
    let (w0, _, l) = creds(9);
    let (_, other_share_p) = Prover::start(CTX, IDP, IDV, &creds(9).0, &creds(9).1).unwrap();
    let (_v, other_share_v, _c) =
        Verifier::respond(CTX, IDP, IDV, &w0, &l, &other_share_p).unwrap();
    assert_eq!(
        s.prover.finish(&other_share_v, &s.confirm_v).unwrap_err(),
        Error::ConfirmationFailed
    );
}

#[test]
fn every_bit_of_confirm_v_is_checked() {
    let (w0, w1, l) = creds(9);
    for bit in 0..256 {
        let (prover, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
        let (_v, share_v, confirm_v) = Verifier::respond(CTX, IDP, IDV, &w0, &l, &share_p).unwrap();
        let mut bytes = *confirm_v.as_bytes();
        bytes[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            prover.finish(&share_v, &ConfirmV::from(bytes)).unwrap_err(),
            Error::ConfirmationFailed,
            "bit {bit}"
        );
    }
}

#[test]
fn tampered_confirm_p_fails() {
    for bit in [0usize, 7, 128, 255] {
        // Verifier::finish consumes the state, so each flip gets a fresh session.
        let s = session();
        let (confirm_p, _) = s.prover.finish(&s.share_v, &s.confirm_v).unwrap();
        let mut bytes = *confirm_p.as_bytes();
        bytes[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            s.verifier.finish(&ConfirmP::from(bytes)).unwrap_err(),
            Error::ConfirmationFailed
        );
    }
    // And the unmodified tag is accepted.
    let s = session();
    let (confirm_p, _) = s.prover.finish(&s.share_v, &s.confirm_v).unwrap();
    assert!(s.verifier.finish(&confirm_p).is_ok());
}

#[test]
fn confirm_tags_are_not_interchangeable() {
    // confirmV offered where confirmP is expected (reflection) is refused.
    let s = session();
    let reflected = ConfirmP::from(*s.confirm_v.as_bytes());
    assert_eq!(
        s.verifier.finish(&reflected).unwrap_err(),
        Error::ConfirmationFailed
    );
    let _ = (&s.share_p, &s.prover);
}

// 5. Context / identity binding ------------------------------------------------------------

#[test]
fn context_mismatch_fails() {
    let (kp, _) = run(5, 5, (CTX, IDP, IDV), (b"other context", IDP, IDV));
    assert_eq!(kp.unwrap_err(), Error::ConfirmationFailed);
}

#[test]
fn id_prover_mismatch_fails() {
    let (kp, _) = run(5, 5, (CTX, IDP, IDV), (CTX, b"intruder", IDV));
    assert_eq!(kp.unwrap_err(), Error::ConfirmationFailed);
}

#[test]
fn id_verifier_mismatch_fails() {
    let (kp, _) = run(5, 5, (CTX, IDP, IDV), (CTX, IDP, b"imposter"));
    assert_eq!(kp.unwrap_err(), Error::ConfirmationFailed);
}

#[test]
fn empty_versus_absent_context_differ() {
    // The context length prefix is always present: "" and "x" must not collide, and an empty
    // context is not the same transcript as moving bytes between fields.
    let (kp, _) = run(5, 5, (b"", b"ab", b"c"), (b"a", b"b", b"c"));
    assert_eq!(kp.unwrap_err(), Error::ConfirmationFailed);
}

// 6. Invalid points ------------------------------------------------------------------------

fn good_share() -> [u8; POINT_LEN] {
    let (w0, w1, _) = creds(11);
    *Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap().1.as_bytes()
}

fn respond_with(share: &[u8; POINT_LEN]) -> Result<()> {
    let (w0, _, l) = creds(11);
    Verifier::respond(CTX, IDP, IDV, &w0, &l, &ShareP::from(*share)).map(|_| ())
}

fn finish_with(share: &[u8; POINT_LEN]) -> Result<()> {
    let (w0, w1, _) = creds(11);
    let (prover, _) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    prover
        .finish(&ShareV::from(*share), &ConfirmV::from([0u8; 32]))
        .map(|_| ())
}

#[test]
fn good_share_is_accepted_by_the_helpers() {
    respond_with(&good_share()).unwrap();
}

#[test]
fn compressed_encoding_rejected() {
    // Compressed points are 33 bytes: the length check applies at the type boundary...
    let g = good_share();
    for tag in [0x02u8, 0x03] {
        let mut c = vec![tag];
        c.extend_from_slice(&g[1..33]);
        assert_eq!(ShareP::from_bytes(&c).unwrap_err(), Error::InvalidLength);
        // ...and a compressed prefix on a 65-byte buffer is refused by the decoder.
        let mut padded = g;
        padded[0] = tag;
        assert_eq!(respond_with(&padded).unwrap_err(), Error::InvalidEncoding);
        assert_eq!(finish_with(&padded).unwrap_err(), Error::InvalidEncoding);
    }
}

#[test]
fn zero_prefix_rejected() {
    assert_eq!(
        respond_with(&[0u8; POINT_LEN]).unwrap_err(),
        Error::InvalidEncoding
    );
    assert_eq!(
        finish_with(&[0u8; POINT_LEN]).unwrap_err(),
        Error::InvalidEncoding
    );
    // The SEC1 identity is the single byte 0x00.
    assert_eq!(
        ShareP::from_bytes(&[0u8]).unwrap_err(),
        Error::InvalidLength
    );
}

#[test]
fn hybrid_encoding_rejected() {
    for tag in [0x06u8, 0x07] {
        let mut s = good_share();
        s[0] = tag;
        assert_eq!(respond_with(&s).unwrap_err(), Error::InvalidEncoding);
        assert_eq!(finish_with(&s).unwrap_err(), Error::InvalidEncoding);
    }
}

#[test]
fn wrong_lengths_rejected() {
    let g = good_share();
    for len in [0usize, 1, 32, 33, 64, 66, 97, 130] {
        let mut b = g.to_vec();
        b.resize(len, 0x11);
        assert_eq!(
            ShareP::from_bytes(&b).unwrap_err(),
            Error::InvalidLength,
            "len {len}"
        );
        assert_eq!(
            ShareV::from_bytes(&b).unwrap_err(),
            Error::InvalidLength,
            "len {len}"
        );
        assert_eq!(
            L::from_bytes(&b).unwrap_err(),
            Error::InvalidLength,
            "len {len}"
        );
    }
    for len in [0usize, 31, 33, 64] {
        let b = vec![0u8; len];
        assert_eq!(ConfirmP::from_bytes(&b).unwrap_err(), Error::InvalidLength);
        assert_eq!(ConfirmV::from_bytes(&b).unwrap_err(), Error::InvalidLength);
    }
}

#[test]
fn off_curve_point_rejected() {
    let mut s = good_share();
    s[64] ^= 0x01; // change one byte of y
    assert_eq!(respond_with(&s).unwrap_err(), Error::NotOnCurve);
    assert_eq!(finish_with(&s).unwrap_err(), Error::NotOnCurve);
}

#[test]
fn off_curve_l_rejected() {
    let (w0, w1, l) = creds(11);
    let (_, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let mut bad = *l.as_bytes();
    bad[64] ^= 0x01;
    let r = Verifier::respond(CTX, IDP, IDV, &w0, &L::from(bad), &share_p);
    assert_eq!(r.unwrap_err(), Error::InvalidRecord);
    assert_eq!(L::parse(&bad).unwrap_err(), Error::InvalidRecord);
    let mut wrong_prefix = *l.as_bytes();
    wrong_prefix[0] = 0x02;
    let r = Verifier::respond(CTX, IDP, IDV, &w0, &L::from(wrong_prefix), &share_p);
    assert_eq!(r.unwrap_err(), Error::InvalidRecord);
    assert_eq!(L::parse(&wrong_prefix).unwrap_err(), Error::InvalidRecord);
}

#[test]
fn coordinate_not_below_field_prime_rejected() {
    let mut s = good_share();
    s[1..33].fill(0xff); // x = 2^256 - 1 >= p
    assert!(respond_with(&s).is_err());
}

/// SP-4: the valid point with x = 0, written as x + p (non-canonical), and its canonical twin.
const NON_CANONICAL: &str = "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";
const CANONICAL: &str = "04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";

#[test]
fn non_canonical_coordinate_rejected_everywhere() {
    let nc: [u8; POINT_LEN] = arr(&unhex(NON_CANONICAL));
    // As shareP and shareV: NotOnCurve is this crate's kind for a non-canonical coordinate.
    assert_eq!(respond_with(&nc).unwrap_err(), Error::NotOnCurve);
    assert_eq!(finish_with(&nc).unwrap_err(), Error::NotOnCurve);
    // As a stored L: InvalidRecord.
    assert_eq!(
        L::parse(&unhex(NON_CANONICAL)).unwrap_err(),
        Error::InvalidRecord
    );
    let (w0, w1, _) = creds(11);
    let (_, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let r = Verifier::respond(CTX, IDP, IDV, &w0, &L::from(nc), &share_p);
    assert_eq!(r.unwrap_err(), Error::InvalidRecord);
}

#[test]
fn canonical_twin_of_the_non_canonical_point_is_accepted() {
    let c: [u8; POINT_LEN] = arr(&unhex(CANONICAL));
    respond_with(&c).unwrap();
    // As shareV the point is accepted as a point; the zero confirmation then fails.
    assert_eq!(finish_with(&c).unwrap_err(), Error::ConfirmationFailed);
    L::parse(&c).unwrap();
}

#[test]
fn negated_l_is_accepted() {
    // SPEC test 6: a valid point's negation (-L) is accepted, by parse and by respond.
    let (w0, w1, l) = creds(11);
    let neg = encode_point(&-decode_point(l.as_bytes()).unwrap()).unwrap();
    let neg_l = L::parse(&neg).unwrap();
    let (_, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    Verifier::respond(CTX, IDP, IDV, &w0, &neg_l, &share_p).unwrap();
}

#[test]
fn l_parse_accepts_a_registered_l() {
    let (_, _, l) = creds(11);
    assert_eq!(L::parse(l.as_bytes()).unwrap(), l);
    l.validate().unwrap();
    for len in [0usize, 64, 66] {
        assert_eq!(L::parse(&vec![4u8; len]).unwrap_err(), Error::InvalidRecord);
    }
}

#[test]
fn bad_stored_l_is_not_reported_as_a_bad_peer_share() {
    let (w0, w1, l) = creds(11);
    let (_, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let mut bad = *l.as_bytes();
    bad[10] ^= 0x40;
    let e = Verifier::respond(CTX, IDP, IDV, &w0, &L::from(bad), &share_p).unwrap_err();
    assert_eq!(e, Error::InvalidRecord);
    assert!(![
        Error::InvalidEncoding,
        Error::NotOnCurve,
        Error::IdentityPoint
    ]
    .contains(&e));
}

#[test]
fn prover_start_reports_an_identity_x_instead_of_panicking() {
    // X = x·P + w0·M is the identity when x·P = -w0·M; only the discrete log of M would find
    // such an x, so here the failure is exercised through encode_point and reject_identity.
    assert_eq!(
        encode_point(&ProjectivePoint::IDENTITY).unwrap_err(),
        Error::IdentityPoint
    );
    assert_eq!(
        reject_identity(ProjectivePoint::IDENTITY).unwrap_err(),
        Error::IdentityPoint
    );
}

#[test]
fn share_equal_to_w0_m_rejected_by_verifier() {
    // X = w0·M, so X - w0·M is the identity.
    let (w0, _, l) = creds(11);
    let x = encode_point(&(constant_point(&M_COMPRESSED) * w0.0)).unwrap();
    let r = Verifier::respond(CTX, IDP, IDV, &w0, &l, &ShareP::from(x));
    assert_eq!(r.unwrap_err(), Error::IdentityPoint);
}

#[test]
fn share_equal_to_w0_n_rejected_by_prover() {
    // Y = w0·N, so Y - w0·N is the identity.
    let (w0, w1, _) = creds(11);
    let (prover, _) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let y = encode_point(&(constant_point(&N_COMPRESSED) * w0.0)).unwrap();
    let r = prover.finish(&ShareV::from(y), &ConfirmV::from([0u8; 32]));
    assert_eq!(r.unwrap_err(), Error::IdentityPoint);
}

#[test]
fn negation_tricks_do_not_yield_the_identity_or_a_key() {
    // X = -w0·M (the negation of the identity-producing share) is a valid, non-identity point:
    // the Verifier must not treat it as the degenerate case, and the result must not confirm.
    let (w0, w1, l) = creds(11);
    let x = encode_point(&-(constant_point(&M_COMPRESSED) * w0.0)).unwrap();
    let (_v, share_v, confirm_v) =
        Verifier::respond(CTX, IDP, IDV, &w0, &l, &ShareP::from(x)).unwrap();
    let (prover, _) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    assert_eq!(
        prover.finish(&share_v, &confirm_v).unwrap_err(),
        Error::ConfirmationFailed
    );

    // The generator's negation as a share: valid curve point, no special case, no panic.
    let neg_g = encode_point(&-ProjectivePoint::GENERATOR).unwrap();
    let _ = Verifier::respond(CTX, IDP, IDV, &w0, &l, &ShareP::from(neg_g));
    let (prover, _) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let r = prover.finish(&ShareV::from(neg_g), &ConfirmV::from([0u8; 32]));
    assert_eq!(r.unwrap_err(), Error::ConfirmationFailed);
}

#[test]
fn identity_l_is_not_encodable_and_zero_l_rejected() {
    let (w0, w1, _) = creds(11);
    let (_, share_p) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    let r = Verifier::respond(CTX, IDP, IDV, &w0, &L::from([0u8; POINT_LEN]), &share_p);
    assert_eq!(r.unwrap_err(), Error::InvalidRecord);
    assert_eq!(
        L::parse(&[0u8; POINT_LEN]).unwrap_err(),
        Error::InvalidRecord
    );
}

#[test]
fn point_helpers_reject_identity() {
    assert_eq!(
        reject_identity(ProjectivePoint::IDENTITY).unwrap_err(),
        Error::IdentityPoint
    );
}

#[test]
fn error_is_secret_free_and_displays() {
    let e: Box<dyn std::error::Error> = Box::new(Error::ConfirmationFailed);
    assert_eq!(e.to_string(), "confirmation failed");
}

#[test]
fn secrets_are_redacted_in_debug() {
    let (w0, w1, _) = creds(1);
    assert_eq!(format!("{w0:?}"), "W0(<redacted>)");
    assert_eq!(format!("{w1:?}"), "W1(<redacted>)");
    let (p, _) = Prover::start(CTX, IDP, IDV, &w0, &w1).unwrap();
    assert_eq!(format!("{p:?}"), "Prover(<redacted>)");
}

// 7. Registration --------------------------------------------------------------------------

/// The group order n of P-256.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn order_plus(delta: u8) -> [u8; 32] {
    // n + delta, with no carry past the last byte for the deltas used (n ends in 0x51).
    let mut b = ORDER;
    b[31] += delta;
    b
}

#[test]
fn pbkdf_output_reduction_known_values() {
    // n + 5 reduces to 5; n - 1 stays n - 1.
    let mut out = [0u8; 80];
    let mut half = [0u8; 40];
    half[8..].copy_from_slice(&order_plus(5));
    out[..40].copy_from_slice(&half);
    out[40..].copy_from_slice(&{
        let mut h = [0u8; 40];
        h[39] = 1;
        h
    });
    let (w0, w1) = w0w1_from_pbkdf_output(&out).unwrap();
    let mut five = [0u8; 32];
    five[31] = 5;
    assert_eq!(*w0.to_bytes(), five);
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(*w1.to_bytes(), one);
}

#[test]
fn pbkdf_output_uses_all_40_bytes() {
    // The high byte matters: [1, 0 x 39] is 2^312 mod n.
    let mut out = [0u8; 80];
    out[0] = 1;
    out[79] = 1;
    let (w0, w1) = w0w1_from_pbkdf_output(&out).unwrap();
    assert_ne!(*w0.to_bytes(), *w1.to_bytes());
    // 2^312 mod n, hex, from Python: pow(2, 312, n)
    // (w1 = 1 here.)
    assert_eq!(
        hex(&*w0.to_bytes()),
        "fffffffeff00000100431905529c01668a4c29445f278194dfbd679dab632551"
    );
}

#[test]
fn pbkdf_output_all_ones_known_reduction() {
    // (2^320 - 1) mod n, computed independently with Python big integers.
    let (w0, w1) = w0w1_from_pbkdf_output(&[0xff; 80]).unwrap();
    let want = "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550";
    assert_eq!(hex(&*w0.to_bytes()), want);
    assert_eq!(hex(&*w1.to_bytes()), want);
}

#[test]
fn pbkdf_output_wrong_lengths_rejected() {
    for len in [0usize, 1, 32, 64, 79, 81, 160] {
        assert_eq!(
            w0w1_from_pbkdf_output(&vec![1u8; len]).unwrap_err(),
            Error::InvalidLength
        );
    }
}

#[test]
fn pbkdf_output_half_equal_to_n_is_zero_scalar() {
    // A 40-byte half equal to n reduces to zero, which is an error (not a silent w = 0).
    let mut half = [0u8; 40];
    half[8..].copy_from_slice(&ORDER);
    let mut one = [0u8; 40];
    one[39] = 1;
    let mut out = [0u8; 80];
    out[..40].copy_from_slice(&half);
    out[40..].copy_from_slice(&one);
    assert_eq!(w0w1_from_pbkdf_output(&out).unwrap_err(), Error::ZeroScalar);
    out[..40].copy_from_slice(&one);
    out[40..].copy_from_slice(&half);
    assert_eq!(w0w1_from_pbkdf_output(&out).unwrap_err(), Error::ZeroScalar);
}

#[test]
fn pbkdf_output_zero_half_rejected() {
    let mut out = [0u8; 80];
    out[79] = 1;
    assert_eq!(w0w1_from_pbkdf_output(&out).unwrap_err(), Error::ZeroScalar);
    let mut out = [0u8; 80];
    out[39] = 1;
    assert_eq!(w0w1_from_pbkdf_output(&out).unwrap_err(), Error::ZeroScalar);
}

#[test]
fn scalar_at_or_above_order_rejected() {
    for delta in [0u8, 1, 5] {
        assert_eq!(
            W0::from_bytes(&order_plus(delta)).unwrap_err(),
            Error::ScalarOutOfRange
        );
        assert_eq!(
            W1::from_bytes(&order_plus(delta)).unwrap_err(),
            Error::ScalarOutOfRange
        );
    }
    assert_eq!(
        W0::from_bytes(&[0xff; 32]).unwrap_err(),
        Error::ScalarOutOfRange
    );
    let mut below = ORDER;
    below[31] -= 1;
    assert!(W0::from_bytes(&below).is_ok());
}

#[test]
fn zero_scalar_rejected() {
    assert_eq!(W0::from_bytes(&[0u8; 32]).unwrap_err(), Error::ZeroScalar);
    assert_eq!(W1::from_bytes(&[0u8; 32]).unwrap_err(), Error::ZeroScalar);
}

#[test]
fn scalar_wrong_length_rejected() {
    for len in [0usize, 31, 33, 40] {
        assert_eq!(
            W0::from_bytes(&vec![1u8; len]).unwrap_err(),
            Error::InvalidLength
        );
    }
}

#[test]
fn scalar_bytes_round_trip() {
    let v = vectors();
    let b = field(&v, "w0");
    assert_eq!(
        W0::from_bytes(&b).unwrap().to_bytes().as_slice(),
        b.as_slice()
    );
}

#[test]
fn pbkdf_input_layout() {
    let got = pbkdf_input(b"pw", b"id1", b"");
    let mut want = Vec::new();
    want.extend_from_slice(&2u64.to_le_bytes());
    want.extend_from_slice(b"pw");
    want.extend_from_slice(&3u64.to_le_bytes());
    want.extend_from_slice(b"id1");
    want.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(*got, want);
}
