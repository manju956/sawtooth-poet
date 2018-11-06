/*
 * Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use sgxffi::ffi;
use sgxffi::ffi::r_sgx_enclave_id_t;
use sgxffi::ffi::r_sgx_signup_info_t;       
use sgxffi::ffi::r_sgx_wait_certificate_t;
use sgxffi::ffi::r_sgx_epid_group_t;
use std::env;
use std::os::raw::c_char;
use std::str;
use std::vec::Vec;
use num::ToPrimitive;
use std::string::String;
use poet2_util;
use std::path::Path;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct WaitCertificate {
    pub duration_id : String,
    pub prev_wait_cert_sig : String,
    pub prev_block_id : String,
    pub block_summary : String,
    pub block_number : u64,
    pub validator_id : String,
    pub wait_time : u64
}

impl Default for WaitCertificate {
    fn default() -> WaitCertificate {
        WaitCertificate {
            duration_id   : String::new(),
            prev_wait_cert_sig : String::new(),
            prev_block_id : String::new(),
            block_summary : String::new(),
            block_number  : 0_u64, 
            validator_id  : String::new(),
            wait_time     : 0_u64, // May be deprecated in later versions
        }
    }
}

pub struct EnclaveConfig {
    pub enclave_id : r_sgx_enclave_id_t, 
    pub signup_info : r_sgx_signup_info_t
}

impl EnclaveConfig {
    pub fn default() -> Self {
        let eid = r_sgx_enclave_id_t { handle : 0,
                                       mr_enclave:0 as *mut c_char,
                                       basename:0 as *mut c_char};
        let signup_info = r_sgx_signup_info_t { handle: 0,
                          poet_public_key : 0 as *mut c_char, 
                          poet_public_key_len : 0,
                          enclave_quote : 0 as *mut c_char}; //Used for IAS operations

        EnclaveConfig {
            enclave_id : eid,
            signup_info: signup_info
        }
    }

    pub fn initialize_enclave(&mut self)
    {
    	let mut eid:r_sgx_enclave_id_t = r_sgx_enclave_id_t { handle: 0,
                                                              mr_enclave:0 as *mut c_char,
                                                              basename:0 as *mut c_char};

        //SPID needs to be read from config file
    	let spid_vec = vec![0x41; 32]; 
        let spid_str = str::from_utf8(&spid_vec).unwrap();

        let mut lib_path = env::current_dir().unwrap();
        lib_path.push("../build/bin/libpoet_enclave.signed.so");
        if ! Path::new(&lib_path).exists(){
            lib_path = PathBuf::from("/usr/lib/libpoet_enclave.signed.so");
            if ! Path::new(&lib_path).exists(){
                 panic!("There is missing libpoet_enclave.signed.so");
            }
        }

        let bin_path = &lib_path.into_os_string().into_string().unwrap();
    	
        ffi::init_enclave(&mut eid, bin_path, spid_str)
			  .expect("Failed to initialize enclave");        
        info!("Initialized enclave");

    	self.enclave_id.handle = eid.handle;
        self.enclave_id.basename = eid.basename;
        self.enclave_id.mr_enclave = eid.mr_enclave;
    }

    pub fn create_signup_info(&mut self, pub_key_hash: &Vec<u8>)
    {
    	let mut eid:r_sgx_enclave_id_t =  self.enclave_id;
        let mut signup:r_sgx_signup_info_t = self.signup_info;
        info!("creating signup_info");

        ffi::create_signup_info(&mut eid, 
                                &(poet2_util::to_hex_string(pub_key_hash.to_vec())),
                                &mut signup).expect("Failed to create signup info");

        self.signup_info.handle = signup.handle;
        self.signup_info.poet_public_key = signup.poet_public_key;
        self.signup_info.poet_public_key_len = signup.poet_public_key_len;
        self.signup_info.enclave_quote = signup.enclave_quote;
    }

    pub fn initialize_wait_certificate(
        eid:r_sgx_enclave_id_t,
        in_prev_wait_cert : String,
        in_prev_wait_cert_sig : String,
        in_validator_id : &Vec<u8>,
        in_poet_pub_key: &String
        ) -> u64 // duration
    {

        let mut duration:u64 = 0_u64;
        let mut eid:r_sgx_enclave_id_t =  eid;
        // initialize wait certificate - to get duration from enclave
        ffi::initialize_wait_cert(&mut eid, &mut duration, 
                                  &in_prev_wait_cert, &in_prev_wait_cert_sig,
                                  &poet2_util::to_hex_string(in_validator_id.to_vec()),
                                  &in_poet_pub_key)
                                  .expect("Failed to initialize Wait certificate");
        
        debug!("Duration fetched from enclave = {:x?}", duration);
        
        duration
    }

    pub fn finalize_wait_certificate(
        eid: r_sgx_enclave_id_t,
        in_wait_cert: String,
        in_prev_block_id : String,
        in_prev_wait_cert_sig: String,
        in_block_summary: String,
        in_wait_time: u64)
        -> (String, String)
    {
        
        let mut eid:r_sgx_enclave_id_t =  eid;

    	let mut wait_cert_info:r_sgx_wait_certificate_t 
                                    = r_sgx_wait_certificate_t { handle: 0,
                                        ser_wait_cert: 0 as *mut c_char,
                                        ser_wait_cert_sign: 0 as *mut c_char};

    	let ret = ffi::finalize_wait_cert(&mut eid, &mut wait_cert_info,
                                          &in_wait_cert, &in_prev_block_id,
                                          &in_prev_wait_cert_sig,
                                          &in_block_summary, &in_wait_time)
                                    .expect("Failed to finalize Wait certificate");

        let wait_cert = ffi::create_string_from_char_ptr(
                             wait_cert_info.ser_wait_cert as *mut c_char);
        
        let wait_cert_sign = ffi::create_string_from_char_ptr(
                             wait_cert_info.ser_wait_cert_sign as *mut c_char);

        info!("wait certificate generated is {:?}", wait_cert);

        //release wait certificate
        let status = ffi::release_wait_certificate(&mut eid, &mut wait_cert_info)
                            .expect("Failed to release wait certificate");

    	(wait_cert, wait_cert_sign)
    }

    pub fn verify_wait_certificate(
        eid: r_sgx_enclave_id_t,
        poet_pub_key: &String,
        wait_cert: &String,
        wait_cert_sign: &String)
        -> bool
    {
        let mut eid:r_sgx_enclave_id_t =  eid;
        let ret = ffi::verify_wait_certificate(&mut eid, &wait_cert.as_str(),
                            &wait_cert_sign.as_str(), &poet_pub_key.as_str());
        ret
    }

    pub fn get_epid_group(&mut self) ->String {
        let mut eid:r_sgx_enclave_id_t = self.enclave_id;
        let mut epid_info:r_sgx_epid_group_t = r_sgx_epid_group_t {
                                                    epid : 0 as *mut c_char};
        let ret = ffi::get_epid_group(&mut eid, &mut epid_info)
                                      .expect("Failed to get EPID group");

        let epid = ffi::create_string_from_char_ptr(epid_info.epid);
        debug!("EPID group = {:?}", epid);
        epid
    }

    pub fn check_if_sgx_simulator(&mut self) -> bool {
        let mut eid:r_sgx_enclave_id_t = self.enclave_id;
        let is_sgx_simulator = ffi::is_sgx_simulator(&mut eid);
        println!("is_sgx_simulator ? {:?}", is_sgx_simulator);
        is_sgx_simulator
    }

    pub fn set_sig_revocation_list(&mut self, sig_rev_list: &String) {
        let mut eid:r_sgx_enclave_id_t = self.enclave_id;
        let ret = ffi::set_sig_revocation_list(&mut eid, 
                                      &sig_rev_list.as_str())
                                .expect("Failed to set signature revocation list");
        debug!("Signature revocation list has been updated");
    }

    pub fn get_signup_parameters(&mut self) ->(String, String) {
        let mut signup_data:r_sgx_signup_info_t = self.signup_info;
        let poet_pub_key = ffi::create_string_from_char_ptr(
                                  signup_data.poet_public_key as *mut c_char);
        let enclave_quote = ffi::create_string_from_char_ptr(
                                  signup_data.enclave_quote as *mut c_char);
        (poet_pub_key, enclave_quote)
    }
}

#[cfg(test)]
mod tests {
    use enclave_sgx::*;
    
    #[test]
    fn test_init_enclave() {
        let mut enclave = EnclaveConfig::default();

        enclave.initialize_enclave();
        assert_eq!( (enclave.enclave_id.handle > 0), true);
    }

    #[test]
    fn test_get_epid_group() {
        let mut enclave = EnclaveConfig::default();
        enclave.initialize_enclave();
        assert_eq!( (enclave.enclave_id.handle > 0), true);

        let ret = enclave.get_epid_group();
        assert_eq!((ret.len() > 0), true);
    }

    #[test]
    fn test_is_sgx_simulator() {
        let mut enclave = EnclaveConfig::default();
        enclave.initialize_enclave();
        assert_eq!( (enclave.enclave_id.handle > 0), true);

        let ret = enclave.check_if_sgx_simulator();
        println!("is_sgx_simulator ? {:?}", ret);
    }

    #[test]
    fn test_create_signup_info() {
        let mut enclave = EnclaveConfig::default();
        enclave.initialize_enclave();
        assert_eq!( (enclave.enclave_id.handle > 0), true);

        let pub_key_hash = vec![0x45; 32];
        enclave.create_signup_info(&pub_key_hash);
        assert_eq!( (enclave.signup_info.handle > 0), true);
    }

    #[test]
    fn test_create_wait_certificate() {
        let mut enclave = EnclaveConfig::default();
        enclave.initialize_enclave();
        assert_eq!( (enclave.enclave_id.handle > 0), true);

        let pub_key_hash = vec![0x45; 32]; 
        enclave.create_signup_info(&pub_key_hash.to_vec());
        assert_eq!( (enclave.signup_info.handle > 0), true);

        let mut duration: u64 = 0x0102030405060708;
        let prev_cert = "".to_string();
        let prev_wait_cert_sig = "".to_string();
        let validator_id = vec![0x41; 32]; 
        let prev_block_id = "abc".to_string();
        let block_summary = "this is first block".to_string();
        let wait_time = 10_u64;

        let (poet_pub_key, enclave_quote) = enclave.get_signup_parameters();

        let ret_dur = EnclaveConfig::initialize_wait_certificate(enclave.enclave_id, prev_cert.clone(),
                                            prev_wait_cert_sig.clone(),
                                            &validator_id, &poet_pub_key);
        assert_eq!((ret_dur > 0), true);

        println!("calling finalize_wait_certificate");
        let (wait_cert, wait_cert_sig) = EnclaveConfig::finalize_wait_certificate(enclave.enclave_id, 
                                                    prev_cert.clone(), prev_block_id.clone(),
                                                    prev_wait_cert_sig.clone(),
                                                    block_summary.clone(), wait_time.clone());
        assert_eq!(wait_cert.is_empty(), false);
        assert_eq!(wait_cert_sig.is_empty(), false);
        println!("wait cert = {}", wait_cert);
        let verify_status = EnclaveConfig::verify_wait_certificate(enclave.enclave_id,
                                    &poet_pub_key, &wait_cert, &wait_cert_sig);
        println!("Wait Certificate verification {}", if verify_status {"Passed"}
                 else {"Failed"});
    }
}
