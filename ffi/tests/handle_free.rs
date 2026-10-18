//! Each handle path (prover/verifier x finish/free) must free its heap block exactly once, and the
//! block must be all zero when the allocator gets it back (the secrets are wiped before the free).
//!
//! A counting global allocator is per test binary, hence this separate integration test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use spake2p_ffi::*;

struct Counting;

/// Address of the block being watched (0 = none), frees seen of it, and whether every one was zero.
static WATCH: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);
static ZERO: AtomicBool = AtomicBool::new(true);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        // Once the watched block has been freed, a new allocation may legitimately reuse its
        // address: stop watching, so a later free of the new block is not miscounted.
        if p as usize == WATCH.load(SeqCst) && FREES.load(SeqCst) > 0 {
            WATCH.store(0, SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if p as usize == WATCH.load(SeqCst) {
            FREES.fetch_add(1, SeqCst);
            // SAFETY: the block is still live and `l.size()` bytes long until System frees it.
            let bytes = unsafe { std::slice::from_raw_parts(p, l.size()) };
            if bytes.iter().any(|&b| b != 0) {
                ZERO.store(false, SeqCst);
            }
        }
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn watch<T>(handle: *mut T) {
    FREES.store(0, SeqCst);
    ZERO.store(true, SeqCst);
    WATCH.store(handle as usize, SeqCst);
}

fn check(what: &str) {
    WATCH.store(0, SeqCst);
    assert_eq!(
        FREES.load(SeqCst),
        1,
        "{what}: handle block freed exactly once"
    );
    assert!(
        ZERO.load(SeqCst),
        "{what}: handle block all zero at dealloc"
    );
}

const CTX: &[u8] = b"alloc test";

struct Fixture {
    w0: [u8; 32],
    w1: [u8; 32],
    l: [u8; 65],
}

fn fixture() -> Fixture {
    let pb = [7u8; 80];
    let (mut w0, mut w1, mut l) = ([0u8; 32], [0u8; 32], [0u8; 65]);
    unsafe {
        assert_eq!(
            spake2p_w0w1_from_pbkdf_output(
                pb.as_ptr(),
                80,
                w0.as_mut_ptr(),
                32,
                w1.as_mut_ptr(),
                32
            ),
            SPAKE2P_OK
        );
        assert_eq!(
            spake2p_register(w1.as_ptr(), 32, l.as_mut_ptr(), 65),
            SPAKE2P_OK
        );
    }
    Fixture { w0, w1, l }
}

fn start(f: &Fixture) -> (*mut Spake2pProver, [u8; 65]) {
    let (mut p, mut share_p) = (ptr::null_mut(), [0u8; 65]);
    let rc = unsafe {
        spake2p_prover_start(
            CTX.as_ptr(),
            CTX.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            f.w0.as_ptr(),
            32,
            f.w1.as_ptr(),
            32,
            &mut p,
            share_p.as_mut_ptr(),
            65,
        )
    };
    assert_eq!(rc, SPAKE2P_OK);
    (p, share_p)
}

fn respond(f: &Fixture, share_p: &[u8; 65]) -> (*mut Spake2pVerifier, [u8; 65], [u8; 32]) {
    let (mut v, mut sv, mut cv) = (ptr::null_mut(), [0u8; 65], [0u8; 32]);
    let rc = unsafe {
        spake2p_verifier_respond(
            CTX.as_ptr(),
            CTX.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            f.w0.as_ptr(),
            32,
            f.l.as_ptr(),
            65,
            share_p.as_ptr(),
            65,
            &mut v,
            sv.as_mut_ptr(),
            65,
            cv.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(rc, SPAKE2P_OK);
    (v, sv, cv)
}

fn p_finish(p: *mut Spake2pProver, sv: &[u8], cv: &[u8]) -> (Spake2pStatus, [u8; 32]) {
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
    (rc, cp)
}

fn v_finish(v: *mut Spake2pVerifier, cp: &[u8]) -> Spake2pStatus {
    let mut key = [0u8; 32];
    unsafe { spake2p_verifier_finish(v, cp.as_ptr(), cp.len(), key.as_mut_ptr(), 32) }
}

// One test function: the watch state is global, so the four paths run in sequence.
#[test]
fn every_handle_path_frees_a_wiped_block_exactly_once() {
    let f = fixture();

    // prover x free
    let (p, _) = start(&f);
    watch(p);
    unsafe { spake2p_prover_free(p) };
    check("prover free");

    // verifier x free
    let (p, share_p) = start(&f);
    let (v, sv, cv) = respond(&f, &share_p);
    watch(v);
    unsafe { spake2p_verifier_free(v) };
    check("verifier free");

    // prover x finish (success, then a failing one)
    let (p2, share_p2) = start(&f);
    let (v2, sv2, cv2) = respond(&f, &share_p2);
    watch(p2);
    let (rc, cp) = p_finish(p2, &sv2, &cv2);
    assert_eq!(rc, SPAKE2P_OK);
    check("prover finish (success)");

    // verifier x finish (success)
    watch(v2);
    assert_eq!(v_finish(v2, &cp), SPAKE2P_OK);
    check("verifier finish (success)");

    // both finish paths on failure
    watch(p);
    assert_eq!(p_finish(p, &sv[..64], &cv).0, SPAKE2P_ERR_INVALID_LENGTH);
    check("prover finish (failure)");

    let (p3, share_p3) = start(&f);
    let (v3, _, _) = respond(&f, &share_p3);
    watch(v3);
    assert_eq!(v_finish(v3, &[0u8; 32]), SPAKE2P_ERR_CONFIRMATION_FAILED);
    check("verifier finish (failure)");
    unsafe { spake2p_prover_free(p3) };
}
