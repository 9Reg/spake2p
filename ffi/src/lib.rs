//! C ABI over the [`spake2p`] crate. See `include/spake2p.h` for the contract.
//!
//! Conventions:
//!
//! * Every function returns a `Spake2pStatus` (an `i32`): 0 is success, anything else an error.
//!   On error no output buffer is written and no output handle is set (it is set to NULL).
//! * Byte strings come as pointer plus length. A NULL pointer is accepted only with length 0.
//! * Output buffers come as pointer plus capacity. They must be non-NULL and at least as large as
//!   the documented output size; larger is fine, only the leading bytes are written. The one
//!   exception is the size probe of `spake2p_pbkdf_input` (NULL `out` with capacity 0).
//! * Output buffers must not overlap an input or each other.
//! * `*_finish` consumes its handle on success and on failure.
//! * No panic crosses the boundary: every body runs under `catch_unwind` and a panic becomes
//!   `SPAKE2P_ERR_PANIC`.

use std::mem::{size_of, MaybeUninit};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::atomic::{compiler_fence, Ordering};

use spake2p::{
    ConfirmP, ConfirmV, Error, Prover, ShareP, ShareV, Verifier, L, PBKDF_OUTPUT_LEN, POINT_LEN,
    SCALAR_LEN, W0, W1,
};

/// Status code returned by every function.
pub type Spake2pStatus = i32;

/// Success.
pub const SPAKE2P_OK: Spake2pStatus = 0;
/// A byte string had the wrong length ([`spake2p::Error::InvalidLength`]).
pub const SPAKE2P_ERR_INVALID_LENGTH: Spake2pStatus = 1;
/// A point was not uncompressed SEC1 ([`spake2p::Error::InvalidEncoding`]).
pub const SPAKE2P_ERR_INVALID_ENCODING: Spake2pStatus = 2;
/// A point was not on the curve ([`spake2p::Error::NotOnCurve`]).
pub const SPAKE2P_ERR_NOT_ON_CURVE: Spake2pStatus = 3;
/// A point was the identity ([`spake2p::Error::IdentityPoint`]).
pub const SPAKE2P_ERR_IDENTITY_POINT: Spake2pStatus = 4;
/// A scalar was not below the group order ([`spake2p::Error::ScalarOutOfRange`]).
pub const SPAKE2P_ERR_SCALAR_OUT_OF_RANGE: Spake2pStatus = 5;
/// A scalar was zero ([`spake2p::Error::ZeroScalar`]).
pub const SPAKE2P_ERR_ZERO_SCALAR: Spake2pStatus = 6;
/// The peer's confirmation tag did not match ([`spake2p::Error::ConfirmationFailed`]).
pub const SPAKE2P_ERR_CONFIRMATION_FAILED: Spake2pStatus = 7;
/// The operating system's random number generator failed ([`spake2p::Error::Rng`]).
pub const SPAKE2P_ERR_RNG: Spake2pStatus = 8;
/// A `spake2p::Error` variant this ABI version does not know.
pub const SPAKE2P_ERR_UNKNOWN: Spake2pStatus = 9;
/// The stored verification value `L` is not a valid point: a local fault, never a bad peer share
/// ([`spake2p::Error::InvalidRecord`]). Appended after `SPAKE2P_ERR_UNKNOWN`; no code was renumbered.
pub const SPAKE2P_ERR_INVALID_RECORD: Spake2pStatus = 10;
/// A required pointer was NULL.
pub const SPAKE2P_ERR_NULL_POINTER: Spake2pStatus = 100;
/// An output buffer was smaller than the documented output size.
pub const SPAKE2P_ERR_BUFFER_TOO_SMALL: Spake2pStatus = 101;
/// An internal panic was caught at the boundary (a bug).
pub const SPAKE2P_ERR_PANIC: Spake2pStatus = 102;

/// Opaque Prover handle (a boxed [`spake2p::Prover`]).
pub struct Spake2pProver(Prover);
/// Opaque Verifier handle (a boxed [`spake2p::Verifier`]).
pub struct Spake2pVerifier(Verifier);

/// Moves the state out of a heap handle, volatile-zeroes the whole block, then frees it.
///
/// `Box::from_raw(p).0` would copy the state to the stack and free the block with `w0`, `w1`,
/// `x` and the key material still in it. Here the block is wiped before it goes back to the
/// allocator; the moved state is zeroised by its own `Drop`.
///
/// # Safety
/// `p` must be a live pointer from `Box::into_raw(Box::new(T))`, not used again afterwards.
unsafe fn take_and_wipe<T>(p: *mut T) -> T {
    // SAFETY: `p` is a live, properly aligned `T` (function contract); the read moves it out and
    // the block is never read as a `T` again.
    let state = unsafe { ptr::read(p) };
    let block = p.cast::<u8>();
    for i in 0..size_of::<T>() {
        // SAFETY: `i < size_of::<T>()`, inside the block `p` points to; volatile so the optimiser
        // may not drop the writes as dead stores before the free.
        unsafe { ptr::write_volatile(block.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: allocated by `Box::new(T)`; `MaybeUninit<T>` has `T`'s layout and no drop glue, so
    // this frees the block without dropping the (already moved-out) contents.
    drop(unsafe { Box::from_raw(p.cast::<MaybeUninit<T>>()) });
    state
}

fn status_of(e: Error) -> Spake2pStatus {
    match e {
        Error::InvalidLength => SPAKE2P_ERR_INVALID_LENGTH,
        Error::InvalidEncoding => SPAKE2P_ERR_INVALID_ENCODING,
        Error::NotOnCurve => SPAKE2P_ERR_NOT_ON_CURVE,
        Error::IdentityPoint => SPAKE2P_ERR_IDENTITY_POINT,
        Error::ScalarOutOfRange => SPAKE2P_ERR_SCALAR_OUT_OF_RANGE,
        Error::ZeroScalar => SPAKE2P_ERR_ZERO_SCALAR,
        Error::ConfirmationFailed => SPAKE2P_ERR_CONFIRMATION_FAILED,
        Error::Rng => SPAKE2P_ERR_RNG,
        Error::InvalidRecord => SPAKE2P_ERR_INVALID_RECORD,
        _ => SPAKE2P_ERR_UNKNOWN,
    }
}

/// Internal error: a status code other than success.
struct Fail(Spake2pStatus);

impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail(status_of(e))
    }
}

/// Runs `f`, turning a panic into `SPAKE2P_ERR_PANIC` and `Ok(())` into `SPAKE2P_OK`.
fn guard(f: impl FnOnce() -> Result<(), Fail>) -> Spake2pStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => SPAKE2P_OK,
        Ok(Err(Fail(code))) => code,
        Err(_) => SPAKE2P_ERR_PANIC,
    }
}

/// Reads an input byte string. NULL is allowed only with `len == 0`.
///
/// # Safety
/// If `ptr` is non-NULL it must be valid for reads of `len` bytes for the duration of the call.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], Fail> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Fail(SPAKE2P_ERR_NULL_POINTER));
    }
    // SAFETY: non-NULL, and the caller guarantees `len` readable bytes (function contract).
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// A checked output buffer: non-NULL and at least `need` bytes of capacity.
struct Out {
    ptr: *mut u8,
    need: usize,
}

impl Out {
    /// Checks capacity. Nothing is written until [`Out::write`].
    fn new(ptr: *mut u8, cap: usize, need: usize) -> Result<Out, Fail> {
        if ptr.is_null() {
            return Err(Fail(SPAKE2P_ERR_NULL_POINTER));
        }
        if cap < need {
            return Err(Fail(SPAKE2P_ERR_BUFFER_TOO_SMALL));
        }
        Ok(Out { ptr, need })
    }

    /// Copies `data` (exactly `need` bytes) to the buffer.
    ///
    /// # Safety
    /// The pointer given to [`Out::new`] must be valid for writes of its stated capacity (at
    /// least `need` bytes), and must not overlap `data`.
    unsafe fn write(&self, data: &[u8]) {
        debug_assert_eq!(data.len(), self.need);
        // SAFETY: `ptr` is non-NULL with capacity >= need (checked in `new`, valid per caller);
        // `data.len() == need`; the buffers are distinct allocations per the caller's contract.
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), self.ptr, data.len()) }
    }
}

// ---------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------

/// Splits an 80-byte PBKDF output into `w0` and `w1` (32 bytes each, big-endian).
///
/// # Safety
/// All pointers must be valid for their stated lengths (see the module conventions).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_w0w1_from_pbkdf_output(
    pbkdf_output: *const u8,
    pbkdf_output_len: usize,
    w0_out: *mut u8,
    w0_cap: usize,
    w1_out: *mut u8,
    w1_cap: usize,
) -> Spake2pStatus {
    guard(|| {
        // SAFETY: caller contract on each pointer/length pair.
        let pbkdf = unsafe { input(pbkdf_output, pbkdf_output_len)? };
        let o0 = Out::new(w0_out, w0_cap, SCALAR_LEN)?;
        let o1 = Out::new(w1_out, w1_cap, SCALAR_LEN)?;
        let (w0, w1) = spake2p::w0w1_from_pbkdf_output(pbkdf)?;
        // SAFETY: both buffers were checked by `Out::new`; they hold fresh local data.
        unsafe {
            o0.write(&*w0.to_bytes());
            o1.write(&*w1.to_bytes());
        }
        Ok(())
    })
}

/// Computes `L = w1·P` (65 bytes) from `w1` (32 bytes).
///
/// # Safety
/// All pointers must be valid for their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_register(
    w1: *const u8,
    w1_len: usize,
    l_out: *mut u8,
    l_cap: usize,
) -> Spake2pStatus {
    guard(|| {
        // SAFETY: caller contract.
        let w1 = W1::from_bytes(unsafe { input(w1, w1_len)? })?;
        let out = Out::new(l_out, l_cap, POINT_LEN)?;
        let l = spake2p::register(&w1)?;
        // SAFETY: `out` checked; `l` is local.
        unsafe { out.write(l.as_bytes()) };
        Ok(())
    })
}

/// Writes the RFC 9383 §3.2 PBKDF input for `password`, `id_prover`, `id_verifier`.
///
/// The required size is `24 + password_len + id_prover_len + id_verifier_len`; it is stored in
/// `*out_len` on success and on `SPAKE2P_ERR_BUFFER_TOO_SMALL`, so a caller may probe with
/// capacity 0 (`out` may be NULL then). `out_len` must be non-NULL. Writing `*out_len` on
/// `SPAKE2P_ERR_BUFFER_TOO_SMALL` is the one exception to "no output on error".
///
/// # Safety
/// All pointers must be valid for their stated lengths; `out_len` for one `size_t` write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_pbkdf_input(
    password: *const u8,
    password_len: usize,
    id_prover: *const u8,
    id_prover_len: usize,
    id_verifier: *const u8,
    id_verifier_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> Spake2pStatus {
    guard(|| {
        if out_len.is_null() {
            return Err(Fail(SPAKE2P_ERR_NULL_POINTER));
        }
        // SAFETY: caller contract on each pointer/length pair.
        let (pw, idp, idv) = unsafe {
            (
                input(password, password_len)?,
                input(id_prover, id_prover_len)?,
                input(id_verifier, id_verifier_len)?,
            )
        };
        let buf = spake2p::pbkdf_input(pw, idp, idv);
        // SAFETY: `out_len` is non-NULL and valid for one write (caller contract).
        unsafe { *out_len = buf.len() };
        // The size probe: NULL `out` with capacity 0 is allowed (the output is never empty).
        if out.is_null() && out_cap == 0 {
            return Err(Fail(SPAKE2P_ERR_BUFFER_TOO_SMALL));
        }
        let o = Out::new(out, out_cap, buf.len())?;
        // SAFETY: `o` checked against `buf.len()`; `buf` is a local allocation.
        unsafe { o.write(&buf) };
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------------------------

/// Starts a Prover. On success `*out_prover` is a new handle and `share_p_out` holds shareP
/// (65 bytes). On failure `*out_prover` is NULL. `w0` and `w1` are 32-byte scalars.
///
/// # Safety
/// All pointers must be valid for their stated lengths; `out_prover` for one pointer write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_prover_start(
    context: *const u8,
    context_len: usize,
    id_prover: *const u8,
    id_prover_len: usize,
    id_verifier: *const u8,
    id_verifier_len: usize,
    w0: *const u8,
    w0_len: usize,
    w1: *const u8,
    w1_len: usize,
    out_prover: *mut *mut Spake2pProver,
    share_p_out: *mut u8,
    share_p_cap: usize,
) -> Spake2pStatus {
    if out_prover.is_null() {
        return SPAKE2P_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL and valid for one pointer write (caller contract).
    unsafe { *out_prover = ptr::null_mut() };
    guard(|| {
        // SAFETY: caller contract on each pointer/length pair.
        let (ctx, idp, idv, w0b, w1b) = unsafe {
            (
                input(context, context_len)?,
                input(id_prover, id_prover_len)?,
                input(id_verifier, id_verifier_len)?,
                input(w0, w0_len)?,
                input(w1, w1_len)?,
            )
        };
        let out = Out::new(share_p_out, share_p_cap, POINT_LEN)?;
        let w0 = W0::from_bytes(w0b)?;
        let w1 = W1::from_bytes(w1b)?;
        let (prover, share_p) = Prover::start(ctx, idp, idv, &w0, &w1)?;
        // SAFETY: `out` checked; `out_prover` non-NULL and writable (checked above).
        unsafe {
            out.write(share_p.as_bytes());
            *out_prover = Box::into_raw(Box::new(Spake2pProver(prover)));
        }
        Ok(())
    })
}

/// Finishes the Prover: checks shareV and confirmV (65 and 32 bytes). On success writes confirmP
/// (32 bytes) and the shared key (32 bytes).
///
/// **The handle is consumed and freed whether this succeeds or fails; it must not be used or
/// freed afterwards.** A NULL handle returns `SPAKE2P_ERR_NULL_POINTER`.
///
/// # Safety
/// `prover` must be NULL or a live handle from `spake2p_prover_start` not yet finished or freed.
/// Other pointers must be valid for their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_prover_finish(
    prover: *mut Spake2pProver,
    share_v: *const u8,
    share_v_len: usize,
    confirm_v: *const u8,
    confirm_v_len: usize,
    confirm_p_out: *mut u8,
    confirm_p_cap: usize,
    key_out: *mut u8,
    key_cap: usize,
) -> Spake2pStatus {
    if prover.is_null() {
        return SPAKE2P_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL, and by contract a live Box-allocated handle; ownership is taken here, the
    // heap block is wiped and freed, and the moved state is zeroised on drop whatever happens next.
    let state = unsafe { take_and_wipe(prover) }.0;
    guard(|| {
        // SAFETY: caller contract on each pointer/length pair.
        let (sv, cv) = unsafe {
            (
                input(share_v, share_v_len)?,
                input(confirm_v, confirm_v_len)?,
            )
        };
        let o_cp = Out::new(confirm_p_out, confirm_p_cap, SCALAR_LEN)?;
        let o_key = Out::new(key_out, key_cap, SCALAR_LEN)?;
        let sv = ShareV::from_bytes(sv)?;
        let cv = ConfirmV::from_bytes(cv)?;
        let (confirm_p, key) = state.finish(&sv, &cv)?;
        // SAFETY: both outputs checked; sources are local.
        unsafe {
            o_cp.write(confirm_p.as_bytes());
            o_key.write(key.as_bytes());
        }
        Ok(())
    })
}

/// Frees a Prover that was never finished, zeroising it. NULL is a no-op.
///
/// # Safety
/// `prover` must be NULL or a live handle not yet finished or freed; it is invalid afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_prover_free(prover: *mut Spake2pProver) {
    if !prover.is_null() {
        // SAFETY: non-NULL live Box-allocated handle per contract; wiped, freed, then dropped.
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { take_and_wipe(prover) })));
    }
}

// ---------------------------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------------------------

/// Answers a Prover's shareP. `w0` is 32 bytes, `l` and `share_p` 65. On success `*out_verifier`
/// is a new handle, `share_v_out` holds shareV (65 bytes) and `confirm_v_out` confirmV (32).
/// On failure `*out_verifier` is NULL.
///
/// # Safety
/// All pointers must be valid for their stated lengths; `out_verifier` for one pointer write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_verifier_respond(
    context: *const u8,
    context_len: usize,
    id_prover: *const u8,
    id_prover_len: usize,
    id_verifier: *const u8,
    id_verifier_len: usize,
    w0: *const u8,
    w0_len: usize,
    l: *const u8,
    l_len: usize,
    share_p: *const u8,
    share_p_len: usize,
    out_verifier: *mut *mut Spake2pVerifier,
    share_v_out: *mut u8,
    share_v_cap: usize,
    confirm_v_out: *mut u8,
    confirm_v_cap: usize,
) -> Spake2pStatus {
    if out_verifier.is_null() {
        return SPAKE2P_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL and valid for one pointer write (caller contract).
    unsafe { *out_verifier = ptr::null_mut() };
    guard(|| {
        // SAFETY: caller contract on each pointer/length pair.
        let (ctx, idp, idv, w0b, lb, spb) = unsafe {
            (
                input(context, context_len)?,
                input(id_prover, id_prover_len)?,
                input(id_verifier, id_verifier_len)?,
                input(w0, w0_len)?,
                input(l, l_len)?,
                input(share_p, share_p_len)?,
            )
        };
        let o_sv = Out::new(share_v_out, share_v_cap, POINT_LEN)?;
        let o_cv = Out::new(confirm_v_out, confirm_v_cap, SCALAR_LEN)?;
        let w0 = W0::from_bytes(w0b)?;
        // Any problem with the stored L (length included) is SPAKE2P_ERR_INVALID_RECORD.
        let l = L::parse(lb)?;
        let share_p = ShareP::from_bytes(spb)?;
        let (verifier, share_v, confirm_v) = Verifier::respond(ctx, idp, idv, &w0, &l, &share_p)?;
        // SAFETY: outputs checked; `out_verifier` non-NULL and writable (checked above).
        unsafe {
            o_sv.write(share_v.as_bytes());
            o_cv.write(confirm_v.as_bytes());
            *out_verifier = Box::into_raw(Box::new(Spake2pVerifier(verifier)));
        }
        Ok(())
    })
}

/// Finishes the Verifier: checks confirmP (32 bytes); on success writes the shared key (32).
///
/// **The handle is consumed and freed whether this succeeds or fails; it must not be used or
/// freed afterwards.** A NULL handle returns `SPAKE2P_ERR_NULL_POINTER`.
///
/// # Safety
/// `verifier` must be NULL or a live handle from `spake2p_verifier_respond` not yet finished or
/// freed. Other pointers must be valid for their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_verifier_finish(
    verifier: *mut Spake2pVerifier,
    confirm_p: *const u8,
    confirm_p_len: usize,
    key_out: *mut u8,
    key_cap: usize,
) -> Spake2pStatus {
    if verifier.is_null() {
        return SPAKE2P_ERR_NULL_POINTER;
    }
    // SAFETY: non-NULL live Box-allocated handle per contract; ownership taken here, block wiped.
    let state = unsafe { take_and_wipe(verifier) }.0;
    guard(|| {
        // SAFETY: caller contract.
        let cp = unsafe { input(confirm_p, confirm_p_len)? };
        let o_key = Out::new(key_out, key_cap, SCALAR_LEN)?;
        let cp = ConfirmP::from_bytes(cp)?;
        let key = state.finish(&cp)?;
        // SAFETY: output checked; source is local.
        unsafe { o_key.write(key.as_bytes()) };
        Ok(())
    })
}

/// Frees a Verifier that was never finished, zeroising it. NULL is a no-op.
///
/// # Safety
/// `verifier` must be NULL or a live handle not yet finished or freed; invalid afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_verifier_free(verifier: *mut Spake2pVerifier) {
    if !verifier.is_null() {
        // SAFETY: non-NULL live Box-allocated handle per contract; wiped, freed, then dropped.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(unsafe { take_and_wipe(verifier) })
        }));
    }
}

/// Checks a stored verification value `L` (65 bytes): `SPAKE2P_OK` if it parses as a valid
/// uncompressed, on-curve, non-identity point, `SPAKE2P_ERR_INVALID_RECORD` for any defect
/// (length included). For checking a record at load time.
///
/// # Safety
/// `l` must be valid for `l_len` bytes (NULL only with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spake2p_l_validate(l: *const u8, l_len: usize) -> Spake2pStatus {
    guard(|| {
        // SAFETY: caller contract.
        let bytes = unsafe { input(l, l_len)? };
        L::parse(bytes)?;
        Ok(())
    })
}

/// Version of this C ABI (bumped on any incompatible change). Currently 1.
pub const SPAKE2P_ABI_VERSION: u32 = 1;

/// The ABI version this library was built with; a client built against a header of a different
/// version must refuse to run.
#[unsafe(no_mangle)]
pub extern "C" fn spake2p_abi_version() -> u32 {
    SPAKE2P_ABI_VERSION
}

/// The PBKDF output length `spake2p_w0w1_from_pbkdf_output` requires (80).
#[unsafe(no_mangle)]
pub extern "C" fn spake2p_pbkdf_output_len() -> usize {
    PBKDF_OUTPUT_LEN
}

#[cfg(test)]
mod tests;
