// @@ This an adaptation of https://github.com/fortanix/rust-mbedtls/blob/master/mbedtls/tests/support/rand.rs

/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use std::os::raw::*;

#[allow(non_camel_case_types)]
type size_t = usize;

use rand::{Rng, XorShiftRng};

/// Not cryptographically secure!!! Use for testing only!!!
pub struct TestRandom(XorShiftRng);

impl mbedtls::rng::RngCallbackMut for TestRandom {
    unsafe extern "C" fn call_mut(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestRandom))
            .0
            .fill_bytes(core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self as *const _ as *mut _
    }
}

impl mbedtls::rng::RngCallback for TestRandom {
    unsafe extern "C" fn call(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        (*(p_rng as *mut TestRandom))
            .0
            .fill_bytes(core::slice::from_raw_parts_mut(data, len));
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        self as *const _ as *mut _
    }
}

/// Not cryptographically secure!!! Use for testing only!!!
pub fn test_rng() -> TestRandom {
    TestRandom(XorShiftRng::new_unseeded())
}
