//! # spake2p
//!
//! An implementation of **SPAKE2+** ([RFC 9383]), the augmented password-authenticated key
//! exchange, for exactly one ciphersuite: **P256-SHA256-HKDF-SHA256-HMAC-SHA256**.
//!
//! SPAKE2+ lets a *Prover* (typically a client that knows a password) and a *Verifier* (typically
//! a server that stores only a verifier derived from the password) agree on a shared key, and
//! prove to each other that they hold it, without ever sending the password. The Verifier stores
//! `(w0, L)`, never `w1`, so stealing the Verifier's database does not directly yield a value the
//! Prover can use to impersonate the client.
//!
//! All group arithmetic comes from RustCrypto's [`p256`]; this crate writes the protocol steps
//! only. The password-hashing step (the PBKDF that turns a password into `w0`/`w1`) is left to the
//! application, as in RFC 9383 §3.2; see [`w0w1_from_pbkdf_output`] and [`pbkdf_input`].
//!
//! ## Message flow
//!
//! ```text
//!   Prover                                     Verifier
//!   Prover::start        -- ShareP ------->    Verifier::respond
//!   Prover::finish       <- ShareV,ConfirmV -- (derives keys, makes ConfirmV)
//!   (checks ConfirmV)    -- ConfirmP ------>   Verifier::finish
//!                                              (checks ConfirmP)
//!   both sides now hold the same SharedKey
//! ```
//!
//! ## Example
//!
//! ```
//! use spake2p::{register, w0w1_from_pbkdf_output, Prover, Verifier};
//!
//! // Registration (once). The application runs its PBKDF of choice over
//! // `spake2p::pbkdf_input(password, id_prover, id_verifier)` to get 80 bytes; a
//! // fixed array stands in for that output here.
//! let pbkdf_output = [0x42u8; 80];
//! let (w0, w1) = w0w1_from_pbkdf_output(&pbkdf_output)?;
//! let l = register(&w1)?; // the Verifier stores (w0, l), never w1
//!
//! let (context, id_prover, id_verifier) = (b"my-app v1".as_slice(), b"client".as_slice(), b"server".as_slice());
//!
//! // Prover -> Verifier
//! let (prover, share_p) = Prover::start(context, id_prover, id_verifier, &w0, &w1)?;
//!
//! // Verifier -> Prover
//! let (verifier, share_v, confirm_v) =
//!     Verifier::respond(context, id_prover, id_verifier, &w0, &l, &share_p)?;
//!
//! // Prover checks the Verifier's confirmation, then answers with its own.
//! let (confirm_p, prover_key) = prover.finish(&share_v, &confirm_v)?;
//!
//! // Verifier checks the Prover's confirmation.
//! let verifier_key = verifier.finish(&confirm_p)?;
//!
//! assert_eq!(prover_key.as_bytes(), verifier_key.as_bytes());
//! # Ok::<(), spake2p::Error>(())
//! ```
//!
//! ## Security notes
//!
//! * Any error ends the exchange: `finish` consumes the state, so a failed run cannot be retried
//!   with the same secrets.
//! * Confirmation tags are compared in constant time. A failed confirmation returns
//!   [`Error::ConfirmationFailed`] and no key material.
//! * Secrets (`x`, `y`, `w0`, `w1`, the encoded `Z` and `V`, and every derived key) are zeroised
//!   when dropped. This is best effort: the compiler or operating system may have copied them
//!   elsewhere, and the curve-point objects of the underlying library are wiped only where this
//!   crate holds them (`Z`, `V` and the unmasked point), not inside `p256`'s temporaries.
//! * A SPAKE2+ run lets an active attacker test exactly one password guess per run. Applications
//!   must rate-limit attempts. A slow PBKDF matters only when the verifier record `(w0, L)` is
//!   persisted and the password is low-entropy (a stolen record then allows an offline search);
//!   for a short-lived record made from a short code, the attempt budget is the defence. See
//!   "Rate limiting" below.
//! * A stored `L` can be checked at load time with [`L::parse`] or [`L::validate`]; a bad one is
//!   then [`Error::InvalidRecord`], a local fault, never a bad peer share.
//! * Identities are bound into the transcript. RFC 9383 recommends non-empty `id_prover` and
//!   `id_verifier`; that is the application's to honour.
//!
//! ## Rate limiting
//!
//! This crate cannot count guesses for you, and what counts as a guess is not obvious. **Every
//! call to [`Verifier::respond`], whatever its outcome, consumes one password guess of the peer**:
//! the attacker receives `confirmV` (and tests its guess offline), or learns from a failure that
//! its guess was exactly right, and then simply never sends `confirmP`. An application that counts
//! only [`Verifier::finish`] failures gives an attacker unlimited guesses. Likewise every
//! [`Prover::finish`] against a peer that has not yet proved itself consumes one guess of that
//! peer. The application must keep a small budget of attempts per password, count them at
//! `respond`, and rotate the password when the budget is spent.
//!
//! [RFC 9383]: https://www.rfc-editor.org/rfc/rfc9383.html

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::{Field, Group};
use p256::{AffinePoint, ProjectivePoint, Scalar, Sec1Point};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(test)]
mod tests;

/// Length in bytes of an uncompressed SEC1 P-256 point: the point as it appears on the wire.
pub const POINT_LEN: usize = 65;
/// Length in bytes of a scalar (`w0`, `w1`) and of a confirmation tag or shared key.
pub const SCALAR_LEN: usize = 32;
/// Length in bytes of the PBKDF output [`w0w1_from_pbkdf_output`] takes: two 40-byte halves.
pub const PBKDF_OUTPUT_LEN: usize = 80;

/// RFC 9383 §4: M, compressed SEC1.
const M_COMPRESSED: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
/// RFC 9383 §4: N, compressed SEC1.
const N_COMPRESSED: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

/// Why an operation failed. Carries no secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A byte string had the wrong length (shares and `L` are 65 bytes, scalars 32, confirmation
    /// tags 32, PBKDF output 80).
    InvalidLength,
    /// A point was not in uncompressed SEC1 form (leading byte other than `0x04`): compressed,
    /// hybrid and identity encodings are all refused.
    InvalidEncoding,
    /// A point was well-formed but is not on the P-256 curve. This is also the kind for a
    /// non-canonical coordinate (a coordinate written as `x + p`, not reduced below the field
    /// prime); Go reports both as `ErrInvalidPoint`, and both drivers as `invalid_point`.
    NotOnCurve,
    /// A received or computed point was the identity element.
    IdentityPoint,
    /// A scalar was greater than or equal to the group order (never silently reduced).
    ScalarOutOfRange,
    /// `w0` or `w1` was zero.
    ZeroScalar,
    /// The peer's confirmation tag did not match. Wrong password, wrong context or identity,
    /// or tampering: the cause is deliberately not distinguished.
    ConfirmationFailed,
    /// The operating system's random number generator failed.
    Rng,
    /// The Verifier's stored `L` is not a valid point (wrong length, not uncompressed SEC1, not on
    /// the curve, or the identity). A local fault with the stored record, never a bad peer share;
    /// check records at load time with [`L::parse`].
    InvalidRecord,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "input has the wrong length",
            Error::InvalidEncoding => "point is not in uncompressed SEC1 form",
            Error::NotOnCurve => "point is not on the P-256 curve",
            Error::IdentityPoint => "point is the identity element",
            Error::ScalarOutOfRange => "scalar is not less than the group order",
            Error::ZeroScalar => "scalar is zero",
            Error::ConfirmationFailed => "confirmation failed",
            Error::Rng => "random number generator failure",
            Error::InvalidRecord => "stored verification value L is invalid",
        })
    }
}

impl std::error::Error for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

// ---------------------------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------------------------

/// Public fixed-size byte newtypes: shares, `L`, confirmations.
macro_rules! public_bytes {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Wraps a byte string, checking only its length. Point validity is checked when the
            /// value is used by the protocol.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                <[u8; $len]>::try_from(bytes).map(Self).map_err(|_| Error::InvalidLength)
            }

            /// The bytes, ready to send or store.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;
            fn try_from(bytes: &[u8]) -> Result<Self> {
                Self::from_bytes(bytes)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                for b in &self.0 {
                    write!(f, "{b:02x}")?;
                }
                f.write_str(")")
            }
        }
    };
}

public_bytes!(
    /// The Prover's public share `X = x·P + w0·M`: 65 bytes, uncompressed SEC1.
    ShareP,
    POINT_LEN
);
public_bytes!(
    /// The Verifier's public share `Y = y·P + w0·N`: 65 bytes, uncompressed SEC1.
    ShareV,
    POINT_LEN
);
public_bytes!(
    /// The Verifier's stored registration point `L = w1·P`: 65 bytes, uncompressed SEC1.
    L,
    POINT_LEN
);
public_bytes!(
    /// The Prover's confirmation tag `HMAC(K_confirmP, shareV)`: 32 bytes.
    ConfirmP,
    SCALAR_LEN
);
public_bytes!(
    /// The Verifier's confirmation tag `HMAC(K_confirmV, shareP)`: 32 bytes.
    ConfirmV,
    SCALAR_LEN
);

// `L` is `w1·P`: public on the wire in the protocol's sense, but anyone holding it can test
// password guesses offline, so a copy kept in memory is wiped when dropped (a `Clone` is wiped
// too). `PartialEq` stays; the rest of the API is unchanged.
impl Zeroize for L {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for L {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for L {}

impl L {
    /// Parses a stored `L`: exactly 65 bytes, uncompressed SEC1, canonical coordinates, on the
    /// curve, not the identity. Call it when loading a record, so a corrupted one is found before
    /// any peer connects. Every failure is [`Error::InvalidRecord`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let l = Self::from_bytes(bytes).map_err(|_| Error::InvalidRecord)?;
        l.validate()?;
        Ok(l)
    }

    /// Checks this `L` like [`L::parse`]: [`Error::InvalidRecord`] unless it is a valid,
    /// non-identity point.
    pub fn validate(&self) -> Result<()> {
        decode_point(&self.0)
            .map(|_| ())
            .map_err(|_| Error::InvalidRecord)
    }
}

/// Secret scalar newtypes (`w0`, `w1`): zeroised on drop, redacted in `Debug`.
macro_rules! secret_scalar {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(Scalar);

        impl $name {
            /// Reads a 32-byte big-endian scalar. A value `>=` the group order, or zero, is an
            /// error; it is never reduced.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let bytes: &[u8; SCALAR_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
                scalar_from_bytes(bytes).map(Self)
            }

            /// The scalar as 32 big-endian bytes, for storage. Treat it as a secret; the returned
            /// buffer is zeroised on drop.
            pub fn to_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
                Zeroizing::new(self.0.to_bytes().into())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_scalar!(
    /// The password-derived scalar `w0`. Held by both the Prover and the Verifier.
    W0
);
secret_scalar!(
    /// The password-derived scalar `w1`. Held by the Prover only; the Verifier stores [`L`].
    W1
);

/// The agreed 32-byte key (`K_shared`), zeroised on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// The key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------

/// Parses a 32-byte big-endian scalar: `>=` the group order and zero are errors.
fn scalar_from_bytes(bytes: &[u8; SCALAR_LEN]) -> Result<Scalar> {
    let s: Option<Scalar> = Option::from(<Scalar as p256::elliptic_curve::PrimeField>::from_repr(
        (*bytes).into(),
    ));
    let s = s.ok_or(Error::ScalarOutOfRange)?;
    if bool::from(s.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    Ok(s)
}

/// Reads `bytes` as a big-endian integer, reduced modulo the group order, using only `p256`
/// scalar arithmetic (Horner's rule, one byte at a time).
fn scalar_reduce_be(bytes: &[u8]) -> Scalar {
    let base = Scalar::from(256u64);
    let mut acc = Zeroizing::new(Scalar::ZERO);
    for &b in bytes {
        *acc = *acc * base + Scalar::from(u64::from(b));
    }
    *acc
}

/// Splits an 80-byte PBKDF output into `(w0, w1)` (RFC 9383 §3.2).
///
/// Each 40-byte half is read as a big-endian integer and reduced modulo the P-256 group order;
/// 40 bytes leaves 64 bits of margin so the reduction is statistically unbiased. Any length other
/// than 80 is [`Error::InvalidLength`]. A zero result (probability about 2⁻²⁵⁶) is
/// [`Error::ZeroScalar`].
pub fn w0w1_from_pbkdf_output(output: &[u8]) -> Result<(W0, W1)> {
    if output.len() != PBKDF_OUTPUT_LEN {
        return Err(Error::InvalidLength);
    }
    let w0 = Zeroizing::new(scalar_reduce_be(&output[..40]));
    let w1 = Zeroizing::new(scalar_reduce_be(&output[40..]));
    if bool::from(w0.is_zero()) || bool::from(w1.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    Ok((W0(*w0), W1(*w1)))
}

/// Computes the Verifier's registration point `L = w1·P`. `w1` is never zero, so the only error
/// is the unreachable identity ([`Error::IdentityPoint`]), reported rather than panicking.
pub fn register(w1: &W1) -> Result<L> {
    Ok(L(encode_point(&(ProjectivePoint::GENERATOR * w1.0))?))
}

/// The RFC 9383 §3.2 recommended PBKDF input:
/// `len(pw)||pw||len(id_prover)||id_prover||len(id_verifier)||id_verifier`, each length an 8-byte
/// little-endian integer. Feed the result to the PBKDF the application chose.
pub fn pbkdf_input(password: &[u8], id_prover: &[u8], id_verifier: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    push_lv(&mut out, password);
    push_lv(&mut out, id_prover);
    push_lv(&mut out, id_verifier);
    out
}

// ---------------------------------------------------------------------------------------------
// Points
// ---------------------------------------------------------------------------------------------

/// Encodes a point as 65-byte uncompressed SEC1. The identity (whose encoding is a single byte)
/// is [`Error::IdentityPoint`]; this function never panics.
fn encode_point(p: &ProjectivePoint) -> Result<[u8; POINT_LEN]> {
    let enc = AffinePoint::from(*p).to_sec1_point(false);
    <[u8; POINT_LEN]>::try_from(enc.as_bytes()).map_err(|_| Error::IdentityPoint)
}

/// Decodes and validates a received point: exactly 65 bytes, leading `0x04`, on the curve, and
/// not the identity.
fn decode_point(bytes: &[u8; POINT_LEN]) -> Result<ProjectivePoint> {
    if bytes[0] != 0x04 {
        return Err(Error::InvalidEncoding);
    }
    let enc = Sec1Point::from_bytes(bytes).map_err(|_| Error::InvalidEncoding)?;
    let affine: Option<AffinePoint> = Option::from(AffinePoint::from_sec1_point(&enc));
    let p = ProjectivePoint::from(affine.ok_or(Error::NotOnCurve)?);
    reject_identity(p)
}

fn reject_identity(p: ProjectivePoint) -> Result<ProjectivePoint> {
    if bool::from(p.is_identity()) {
        Err(Error::IdentityPoint)
    } else {
        Ok(p)
    }
}

/// Decodes a hard-coded compressed constant (M or N).
fn constant_point(compressed: &[u8; 33]) -> ProjectivePoint {
    let enc = Sec1Point::from_bytes(compressed).expect("constant is well-formed SEC1");
    let affine: Option<AffinePoint> = Option::from(AffinePoint::from_sec1_point(&enc));
    ProjectivePoint::from(affine.expect("RFC 9383 constant is on the curve"))
}

// ---------------------------------------------------------------------------------------------
// Transcript and key schedule
// ---------------------------------------------------------------------------------------------

/// Appends `len(s)||s`, the length being 8 bytes little-endian (RFC 9383 §3).
fn push_lv(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s);
}

/// Everything derived from the transcript. Zeroised on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Derived {
    #[cfg(test)]
    tt: Vec<u8>,
    #[cfg(test)]
    z: [u8; POINT_LEN],
    #[cfg(test)]
    v: [u8; POINT_LEN],
    #[cfg(test)]
    k_main: [u8; 32],
    k_confirm_p: [u8; 32],
    k_confirm_v: [u8; 32],
    k_shared: [u8; 32],
}

/// Builds TT (RFC 9383 §3.3) and runs the key schedule (§3.4).
///
/// `z` and `v` must already be checked non-identity.
#[allow(clippy::too_many_arguments)]
fn derive(
    context: &[u8],
    id_prover: &[u8],
    id_verifier: &[u8],
    share_p: &[u8; POINT_LEN],
    share_v: &[u8; POINT_LEN],
    z: &ProjectivePoint,
    v: &ProjectivePoint,
    w0: &Scalar,
) -> Result<Derived> {
    let m = encode_point(&constant_point(&M_COMPRESSED))?;
    let n = encode_point(&constant_point(&N_COMPRESSED))?;
    let z_bytes = Zeroizing::new(encode_point(z)?);
    let v_bytes = Zeroizing::new(encode_point(v)?);
    let w0_bytes = Zeroizing::new(<[u8; 32]>::from(w0.to_bytes()));

    let mut tt = Zeroizing::new(Vec::with_capacity(
        8 * 9 + 5 * POINT_LEN + 2 * POINT_LEN + 64,
    ));
    push_lv(&mut tt, context);
    push_lv(&mut tt, id_prover);
    push_lv(&mut tt, id_verifier);
    push_lv(&mut tt, &m);
    push_lv(&mut tt, &n);
    push_lv(&mut tt, share_p);
    push_lv(&mut tt, share_v);
    push_lv(&mut tt, &*z_bytes);
    push_lv(&mut tt, &*v_bytes);
    push_lv(&mut tt, &*w0_bytes);

    let k_main = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&*tt)));
    let hk = Hkdf::<Sha256>::new(None, &*k_main);
    let mut confirm_keys = Zeroizing::new([0u8; 64]);
    hk.expand(b"ConfirmationKeys", &mut *confirm_keys)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut k_shared = [0u8; 32];
    hk.expand(b"SharedKey", &mut k_shared)
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    let mut k_confirm_p = [0u8; 32];
    let mut k_confirm_v = [0u8; 32];
    k_confirm_p.copy_from_slice(&confirm_keys[..32]);
    k_confirm_v.copy_from_slice(&confirm_keys[32..]);

    Ok(Derived {
        #[cfg(test)]
        tt: tt.to_vec(),
        #[cfg(test)]
        z: *z_bytes,
        #[cfg(test)]
        v: *v_bytes,
        #[cfg(test)]
        k_main: *k_main,
        k_confirm_p,
        k_confirm_v,
        k_shared,
    })
}

fn hmac_tag(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality of two tags.
fn tags_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

/// A uniformly random non-zero scalar from the operating system's CSPRNG, by rejection sampling:
/// 32 random bytes into a zeroising buffer, retried while the value is `>=` the group order or
/// zero (about 2^-32 per draw). Rejection depends only on the discarded draw, so it leaks nothing
/// about the accepted value, and no unwiped copy of the bytes is left behind.
fn random_scalar() -> Result<Scalar> {
    let mut buf = Zeroizing::new([0u8; SCALAR_LEN]);
    loop {
        getrandom::fill(&mut *buf).map_err(|_| Error::Rng)?;
        if let Ok(s) = scalar_from_bytes(&buf) {
            return Ok(s);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------------------------

/// The Prover's state between [`Prover::start`] and [`Prover::finish`]. Zeroised on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Prover {
    context: Vec<u8>,
    id_prover: Vec<u8>,
    id_verifier: Vec<u8>,
    w0: Scalar,
    w1: Scalar,
    x: Scalar,
    share_p: [u8; POINT_LEN],
}

impl fmt::Debug for Prover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prover(<redacted>)")
    }
}

impl Prover {
    /// Starts an exchange: picks `x` from the OS CSPRNG and returns the state together with
    /// `shareP = x·P + w0·M` to send to the Verifier.
    pub fn start(
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        w0: &W0,
        w1: &W1,
    ) -> Result<(Prover, ShareP)> {
        Self::start_with_x(context, id_prover, id_verifier, w0, w1, random_scalar()?)
    }

    /// Like [`Prover::start`] with `x` supplied. Reachable only from tests.
    #[cfg(test)]
    pub(crate) fn start_with_scalar(
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        w0: &W0,
        w1: &W1,
        x: &[u8; 32],
    ) -> (Prover, ShareP) {
        let x = scalar_from_bytes(x).expect("test x is a valid scalar");
        Self::start_with_x(context, id_prover, id_verifier, w0, w1, x).expect("test x is fine")
    }

    fn start_with_x(
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        w0: &W0,
        w1: &W1,
        x: Scalar,
    ) -> Result<(Prover, ShareP)> {
        let m = constant_point(&M_COMPRESSED);
        let w0m = Zeroizing::new(m * w0.0);
        let big_x = ProjectivePoint::GENERATOR * x + *w0m;
        // X is the identity only if x·P = -w0·M, which an honest random x makes negligible; it is
        // an error, never a panic.
        let share_p = encode_point(&reject_identity(big_x)?)?;
        let prover = Prover {
            context: context.to_vec(),
            id_prover: id_prover.to_vec(),
            id_verifier: id_verifier.to_vec(),
            w0: w0.0,
            w1: w1.0,
            x,
            share_p,
        };
        Ok((prover, ShareP(share_p)))
    }

    /// Finishes the exchange. Validates `share_v`, derives the keys, and checks `confirm_v` in
    /// constant time. Only if it matches does it return the Prover's confirmation tag (to send
    /// to the Verifier) and the shared key; otherwise it returns an error and nothing else.
    pub fn finish(self, share_v: &ShareV, confirm_v: &ConfirmV) -> Result<(ConfirmP, SharedKey)> {
        let derived = self.derive_keys(share_v)?;
        let expected = hmac_tag(&derived.k_confirm_v, &self.share_p);
        if !tags_equal(&expected, &confirm_v.0) {
            return Err(Error::ConfirmationFailed);
        }
        let confirm_p = ConfirmP(hmac_tag(&derived.k_confirm_p, &share_v.0));
        Ok((confirm_p, SharedKey(derived.k_shared)))
    }

    fn derive_keys(&self, share_v: &ShareV) -> Result<Derived> {
        let y_pt = decode_point(&share_v.0)?;
        let n = constant_point(&N_COMPRESSED);
        // Y - w0·N
        let w0n = Zeroizing::new(n * self.w0);
        let diff = Zeroizing::new(reject_identity(y_pt - *w0n)?);
        // h = 1 for P-256, so no cofactor multiplication.
        let z = Zeroizing::new(reject_identity(*diff * self.x)?);
        let v = Zeroizing::new(reject_identity(*diff * self.w1)?);
        derive(
            &self.context,
            &self.id_prover,
            &self.id_verifier,
            &self.share_p,
            &share_v.0,
            &z,
            &v,
            &self.w0,
        )
    }

    /// Test hook: everything derived for `share_v`, without checking any confirmation.
    #[cfg(test)]
    fn derived_for_test(&self, share_v: &ShareV) -> Derived {
        self.derive_keys(share_v).expect("valid share")
    }
}

// ---------------------------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------------------------

/// The Verifier's state between [`Verifier::respond`] and [`Verifier::finish`]. Zeroised on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Verifier {
    share_v: [u8; POINT_LEN],
    k_confirm_p: [u8; 32],
    k_shared: [u8; 32],
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Verifier(<redacted>)")
    }
}

impl Verifier {
    /// Answers the Prover's `share_p`. Validates `share_p` and `l`, picks `y` from the OS CSPRNG,
    /// and returns the state, `shareV = y·P + w0·N`, and `confirmV = HMAC(K_confirmV, shareP)`.
    pub fn respond(
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        w0: &W0,
        l: &L,
        share_p: &ShareP,
    ) -> Result<(Verifier, ShareV, ConfirmV)> {
        let y = random_scalar()?;
        Self::respond_with_y(context, id_prover, id_verifier, w0, l, share_p, y)
            .map(|(v, s, c, _)| (v, s, c))
    }

    /// Like [`Verifier::respond`] with `y` supplied, also returning the derived values. Tests only.
    #[cfg(test)]
    pub(crate) fn respond_with_scalar(
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        w0: &W0,
        l: &L,
        share_p: &ShareP,
        y: &[u8; 32],
    ) -> Result<(Verifier, ShareV, ConfirmV, Derived)> {
        let y = scalar_from_bytes(y).expect("test y is a valid scalar");
        Self::respond_with_y(context, id_prover, id_verifier, w0, l, share_p, y)
    }

    fn respond_with_y(
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        w0: &W0,
        l: &L,
        share_p: &ShareP,
        y: Scalar,
    ) -> Result<(Verifier, ShareV, ConfirmV, Derived)> {
        let y = Zeroizing::new(y);
        // A bad stored L is the application's own fault, not the peer's: its own error kind.
        let l_pt = decode_point(&l.0).map_err(|_| Error::InvalidRecord)?;
        let x_pt = decode_point(&share_p.0)?;
        let m = constant_point(&M_COMPRESSED);
        let n = constant_point(&N_COMPRESSED);

        let w0n = Zeroizing::new(n * w0.0);
        let w0m = Zeroizing::new(m * w0.0);
        let big_y = ProjectivePoint::GENERATOR * *y + *w0n;
        let share_v = encode_point(&reject_identity(big_y)?)?;

        // X - w0·M
        let diff = Zeroizing::new(reject_identity(x_pt - *w0m)?);
        // h = 1 for P-256, so no cofactor multiplication.
        let z = Zeroizing::new(reject_identity(*diff * *y)?);
        let v = Zeroizing::new(reject_identity(l_pt * *y)?);

        let derived = derive(
            context,
            id_prover,
            id_verifier,
            &share_p.0,
            &share_v,
            &z,
            &v,
            &w0.0,
        )?;
        let confirm_v = ConfirmV(hmac_tag(&derived.k_confirm_v, &share_p.0));
        let state = Verifier {
            share_v,
            k_confirm_p: derived.k_confirm_p,
            k_shared: derived.k_shared,
        };
        Ok((state, ShareV(share_v), confirm_v, derived))
    }

    /// Finishes the exchange: checks `confirm_p` in constant time and, only if it matches,
    /// returns the shared key.
    pub fn finish(self, confirm_p: &ConfirmP) -> Result<SharedKey> {
        let expected = hmac_tag(&self.k_confirm_p, &self.share_v);
        if !tags_equal(&expected, &confirm_p.0) {
            return Err(Error::ConfirmationFailed);
        }
        Ok(SharedKey(self.k_shared))
    }
}
