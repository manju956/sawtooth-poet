/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

pub mod ffi;

#[cfg(test)]
mod tests {
    use super::*;
    use ffi::r_sgx_enclave_id_t;
    use ffi::r_sgx_epid_group_t;
    use ffi::r_sgx_signup_info_t;
    use ffi::r_sgx_wait_certificate_t;
    use std::os::raw::c_char;
    use std::ptr;
    use std::str;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    fn initialize_enclave(eid: &mut r_sgx_enclave_id_t) -> String {
        //spid should be a valid UTF-8 string of length 32. create all AAAAA's
        let spid_vec = vec![0x41; 32];
        let spid_str = str::from_utf8(&spid_vec).unwrap();
        let mut lib_path = std::env::current_dir().unwrap();
        lib_path.push("../../build/bin/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();
        let ret = ffi::init_enclave(eid, bin_path, spid_str).expect("Failed to initialize enclave");
        ret
    }

    #[test]
    fn test_init_enclave() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let ret = initialize_enclave(&mut eid);
        assert_eq!(ret, "Success");
    }

    #[test]
    fn test_is_sgx_simulator() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let ret = initialize_enclave(&mut eid);
        assert_eq!(ret, "Success");

        //check if SGX is running in simulator mode
        let mut sgx_simulator: bool = false;
        let ret = ffi::is_sgx_simulator(&mut eid, &mut sgx_simulator)
            .expect("Failed to check SGX simulator");
        assert_eq!(ret, "Success");
    }

    fn create_signup_info(
        eid: &mut r_sgx_enclave_id_t,
        signup_info: &mut r_sgx_signup_info_t,
        opk_hash_vec: &str,
    ) -> String {
        let ret = initialize_enclave(eid);
        assert_eq!(ret, "Success");
        let ret = ffi::create_signup_info(eid, &opk_hash_vec, signup_info)
            .expect("Failed to create signup info");
        ret
    }

    #[test]
    fn test_create_signup_info() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let mut signup_info: r_sgx_signup_info_t = r_sgx_signup_info_t {
            handle: 0,
            poet_public_key: ptr::null_mut(),
            poet_public_key_len: 0,
            enclave_quote: ptr::null_mut(),
        };

        let opk_hash_vec = "ABCD";
        let ret = create_signup_info(&mut eid, &mut signup_info, &opk_hash_vec);
        assert_eq!(ret, "Success");
    }

    fn initialize_wait_certificate(
        eid: &mut r_sgx_enclave_id_t,
        signup_info: &mut r_sgx_signup_info_t,
    ) -> String {
        let mut duration: u64 = 0x0102030405060708;
        let prev_cert = "";
        let prev_wait_cert_sig = "";
        let validator_id = "123";

        let opk_hash_vec = "ABCD1234";
        let ret = create_signup_info(eid, signup_info, &opk_hash_vec);
        assert_eq!(ret, "Success");

        let poet_public_key =
            unsafe { ffi::create_string_from_char_ptr(signup_info.poet_public_key as *mut c_char) };

        let ret = ffi::initialize_wait_cert(
            eid,
            &mut duration,
            &prev_cert,
            &prev_wait_cert_sig,
            &validator_id,
            &poet_public_key,
        )
        .expect("Failed to initialize Wait certificate");
        ret
    }

    fn finalize_wait_certificate(
        eid: &mut r_sgx_enclave_id_t,
        wait_cert_info: &mut r_sgx_wait_certificate_t,
    ) -> String {
        let prev_cert = "";
        let prev_block_id = "abc";
        let prev_wait_cert_sig = "";
        let block_summary = "this is first block";
        let wait_time = 10_u64;
        let mut verify_wait_cert_status: bool = false;

        let ret = ffi::finalize_wait_cert(
            eid,
            wait_cert_info,
            &prev_cert,
            &prev_block_id,
            &prev_wait_cert_sig,
            &block_summary,
            wait_time,
        )
        .expect("Failed to finalize Wait certificate");
        ret
    }

    #[test]
    fn test_create_wait_cert() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let mut wait_cert_info: r_sgx_wait_certificate_t = r_sgx_wait_certificate_t {
            handle: 0,
            ser_wait_cert: ptr::null_mut(),
            ser_wait_cert_sign: ptr::null_mut(),
        };

        let mut signup_info: r_sgx_signup_info_t = r_sgx_signup_info_t {
            handle: 0,
            poet_public_key: ptr::null_mut(),
            poet_public_key_len: 0,
            enclave_quote: ptr::null_mut(),
        };
        let ret = initialize_wait_certificate(&mut eid, &mut signup_info);
        assert_eq!(ret, "Success");

        let ret = finalize_wait_certificate(&mut eid, &mut wait_cert_info);
        assert_eq!(ret, "Success");

        let wait_cert = unsafe {
            ffi::create_string_from_char_ptr(wait_cert_info.ser_wait_cert as *mut c_char)
        };
        let wait_cert_sig = unsafe {
            ffi::create_string_from_char_ptr(wait_cert_info.ser_wait_cert_sign as *mut c_char)
        };
        let ppk_str: String =
            unsafe { ffi::create_string_from_char_ptr(signup_info.poet_public_key as *mut c_char) };

        let mut verify_wait_cert_status: bool = false;
        let ret = ffi::verify_wait_certificate(
            &mut eid,
            &wait_cert.as_str(),
            &wait_cert_sig.as_str(),
            &ppk_str.as_str(),
            &mut verify_wait_cert_status,
        )
        .expect("Failed to verify wait certificate");

        let ret = ffi::release_wait_certificate(&mut eid, &mut wait_cert_info)
            .expect("Failed to release wait certificate");
        assert_eq!(ret, "Success");
    }

    #[test]
    fn test_release_signup_info() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let mut signup_info: r_sgx_signup_info_t = r_sgx_signup_info_t {
            handle: 0,
            poet_public_key: ptr::null_mut(),
            poet_public_key_len: 0,
            enclave_quote: ptr::null_mut(),
        };
        let opk_hash_vec = "ABCD1234";
        let ret = create_signup_info(&mut eid, &mut signup_info, &opk_hash_vec);
        assert_eq!(ret, "Success");

        let ret = ffi::release_signup_info(&mut eid, &mut signup_info)
            .expect("Failed to release signup info");
        assert_eq!(ret, "Success");
    }

    #[test]
    fn test_create_string_from_char_ptr() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let ret = initialize_enclave(&mut eid);
        assert_eq!(ret, "Success");

        let basename = unsafe { ffi::create_string_from_char_ptr(eid.basename as *mut c_char) };
        assert_eq!(basename.is_empty(), false);
    }

    #[test]
    fn test_terminate_enclave() {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: ptr::null_mut(),
            basename: ptr::null_mut(),
            epid_group: ptr::null_mut(),
        };
        let ret = initialize_enclave(&mut eid);
        assert_eq!(ret, "Success");

        let ret = ffi::free_enclave(&mut eid).expect("Failed to terminate enclave");
        assert_eq!(ret, "Success");
    }
}
