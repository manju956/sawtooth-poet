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
#include <vector>

void test_poetInitialize();

void test_poetCreateSignupData(char *poetPublicKey, size_t poetPubKeyLen,
                               char *enclaveQuote, size_t enclaveQuoteLen );

void test_poetVerifySignupInfo(char *poetPublicKey, char *enclaveQuote);

void test_poetInitializeWaitCert(char *poetPublicKey, size_t poetPubKeyLen);

void test_poetFinalizeWaitCert(char *serialWaitCert, size_t serialWaitCertLen,
                               char *serialWaitCertSig, size_t serialWaitCertSigLen);

void test_deserializeWaitCert(char *serialWaitCert, char *serialWaitCertSig);

void test_poetVerifyWaitCert(char *serialWaitCert, char *serialWaitCertSig,
                             char *poetPublicKey);

void test_enclaveCharacteristics();

void test_getEpidGroup();

void test_poetTerminate();

