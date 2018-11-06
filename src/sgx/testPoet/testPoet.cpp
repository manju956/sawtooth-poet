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

#include <iostream>
#include <sstream>

#include "testPoet.h"
#include "utils.h"
#include "common.h"
#include "poet.h"
#include "poet_enclave.h"

namespace sp = sawtooth::poet;

int main(int argc, char **argv) {
    test_poetInitialize();   
 
    test_enclaveCharacteristics();

    test_getEpidGroup();

    StringBuffer poetPublicKey(Poet_GetPublicKeySize());
    StringBuffer enclaveQuote(Poet_GetEnclaveQuoteSize());

    test_poetCreateSignupData(poetPublicKey.data(), poetPublicKey.length,
                              enclaveQuote.data(), enclaveQuote.length);

    test_poetVerifySignupInfo(poetPublicKey.data(), enclaveQuote.data());

    test_poetInitializeWaitCert(poetPublicKey.data(), poetPublicKey.length);

    StringBuffer waitCert(Poet_GetWaitCertificateSize());
    StringBuffer waitCertSig(Poet_GetSignatureSize());

    test_poetFinalizeWaitCert(waitCert.data(), waitCert.length, waitCertSig.data(), waitCertSig.length);

    test_deserializeWaitCert(waitCert.data(), waitCertSig.data());

    test_poetVerifyWaitCert(waitCert.data(), waitCertSig.data(), poetPublicKey.data());

    test_poetTerminate();

    return 0;
}

void test_poetInitialize() {
    const char *enclavePath = "../../build/bin/libpoet_enclave.signed.so";

    //spid should be a valid UTF-8 string of length 32. create all AAAAA's
    const char *spid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MyLog(POET_LOG_INFO, "Initializing SGX Poet enclave\n");
    poet_err_t ret = Poet_Initialize(enclavePath, spid, MyLog);

    if(ret != POET_SUCCESS) {
        printf("ERROR: test_poetInitialize\n");
    } else {
        printf("SUCCESS: test_poetInitialize\n");
    }
}

void test_poetCreateSignupData(char *poetPublicKey, size_t poetPubKeyLen,
                               char *enclaveQuote, size_t enclaveQuoteLen ) {
    const char *pubKeyHash = "ABCD1234";
    poet_err_t ret = Poet_CreateSignupData(pubKeyHash, poetPublicKey, 
                                           poetPubKeyLen, enclaveQuote,
                                           enclaveQuoteLen);
    if(ret != POET_SUCCESS) {
        printf("ERROR: test_poetCreateSignupData\n");
    } else {
        printf("SUCCESS: test_poetCreateSignupData\n");
    }
}

void test_poetVerifySignupInfo(char *poetPublicKey, char *enclaveQuote) {
    const char *pubKeyHash = "ABCD1234";
    poet_err_t ret = Poet_VerifySignupInfo(pubKeyHash, poetPublicKey, 
                                           enclaveQuote);
    if(ret != POET_SUCCESS){
        printf("ERROR: test_poetVerifySignupInfo\n");
    } else {
        printf("SUCCESS: test_poetVerifySignupInfo\n");
    }
}


void test_poetInitializeWaitCert(char *poetPublicKey, size_t poetPubKeyLen) {
    uint8_t duration[8];
    std::string prevWaitCert = "";
    std::string prevWaitCertSig = "";
    std::string validatorId = "0x12345";

    poet_err_t ret = Poet_InitializeWaitCertificate(prevWaitCert.c_str(), prevWaitCert.length(),
                                                validatorId.c_str(), validatorId.length(),
                                                prevWaitCertSig.c_str(), prevWaitCertSig.length(),
                                                poetPublicKey, poetPubKeyLen,
                                                duration, sizeof(duration)/sizeof(*duration));
    if(ret != POET_SUCCESS) {
        printf("ERROR: test_poetInitializeWaitCert\n");
    } else {
        printf("SUCCESS: test_poetInitializeWaitCert\n");
    }
}


void test_poetFinalizeWaitCert(char *serialWaitCert, size_t serialWaitCertLen,
                               char *serialWaitCertSig, size_t serialWaitCertSigLen) {
    std::string prevWaitCert = "";
    std::string prevWaitCertSig = "";
    std::string prevBlockId = "abc";
    std::string blockSummary = "finalizing wait cert";
    uint64_t waitTime = 1;

    poet_err_t ret = Poet_FinalizeWaitCertificate(prevWaitCert.c_str(), prevWaitCert.length(),
                                                  prevBlockId.c_str(), prevBlockId.length(),
                                                  prevWaitCertSig.c_str(), prevWaitCertSig.length(),
                                                  blockSummary.c_str(), blockSummary.length(),
                                                  waitTime, 
                                                  serialWaitCert, serialWaitCertLen,
                                                  serialWaitCertSig, serialWaitCertSigLen);

    if(ret != POET_SUCCESS) {
        printf("ERROR: test_poetFinalizeWaitCert\n");
    } else {
        printf("SUCCESS: test_poetFinalizeWaitCert\n");
    }

}

void test_deserializeWaitCert(char *serialWaitCert, char *serialWaitCertSig) {

    WaitCertificate *waitCertObj = deserialize_wait_certificate(serialWaitCert, serialWaitCertSig);
    if(waitCertObj != NULL) {
        printf("SUCCESS: test_deserializeWaitCert\n");
    } else {
        printf("ERROR: test_deserializeWaitCert\n");
    }
}

void test_poetVerifyWaitCert(char *serialWaitCert, char *serialWaitCertSig,
                             char *poetPublicKey) {

    poet_err_t ret = Poet_VerifyWaitCertificate(serialWaitCert, serialWaitCertSig,
                                                poetPublicKey);

    if(ret != POET_SUCCESS) {
        printf("ERROR: test_poetVerifyWaitCert\n");
    } else {
        printf("SUCCESS: test_poetVerifyWaitCert\n");
    }
}

void test_getEpidGroup() {
    StringBuffer epidBuffer(Poet_GetEpidGroupSize());
    poet_err_t ret = Poet_GetEpidGroup(epidBuffer.data(), epidBuffer.length);
    if(ret != POET_SUCCESS) {
        printf("ERROR: test_getEpidGroup\n");
    } else {
        printf("epid group %s\n", epidBuffer.data());
        printf("SUCCESS: test_getEpidGroup\n");
    }
}

void test_enclaveCharacteristics() {
    StringBuffer mrEnclaveBuffer(Poet_GetEnclaveMeasurementSize());
    StringBuffer basenameBuffer(Poet_GetEnclaveBasenameSize());
    poet_err_t ret = Poet_GetEnclaveCharacteristics( mrEnclaveBuffer.data(), 
                                    mrEnclaveBuffer.length, basenameBuffer.data(),
                                    basenameBuffer.length);

    if(ret != POET_SUCCESS) {
        printf("ERROR: test_enclaveCharacteristics\n");
    } else {
        printf("enclave basename %s\n", basenameBuffer.data());
        printf("enclave measurement %s\n", mrEnclaveBuffer.data());
        printf("SUCCESS: test_enclaveCharacteristics\n");
    }
}

void test_poetTerminate() {
    poet_err_t ret = Poet_Terminate();
    if(ret != POET_SUCCESS) {
        printf("ERROR: test_poetTerminate\n");
    } else {
        printf("SUCCESS: test_poetTerminate\n");
    }
}

