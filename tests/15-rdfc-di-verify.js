/*!
 * Copyright 2023 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import {
  checkDataIntegrityProofVerifyErrors
} from 'data-integrity-test-suite-assertion';
import {
  cryptosuite as ecdsaRdfc2019Cryptosuite
} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {endpoints} from 'vc-test-suite-implementations';
import {filterVerifiers} from './helpers.js';
import {getMultiKey} from './vc-generator/key-gen.js';
import {getSuiteConfig} from './test-config.js';

const {tags, vectors, credentials} = getSuiteConfig('ecdsa-rdfc-2019');

for(const vcVersion of vectors.vcTypes) {
  const key = await getMultiKey({keyType: 'P-256'});
  const {document} = credentials.verify[vcVersion];
  const {match} = endpoints.filter({
    // create a filter for endpoints by vc version
    filter: filterVerifiers.bind({
      vc: {
        version: vcVersion,
        // this will be the default supported version
        // if an endpoint does not explictly declare
        // which vc version is supported
        default: '1.1'
      },
      tags
    })
  });
  const optionalTests = {
    proofChain: true
  };
  // options for the DI Verifier Suite
  checkDataIntegrityProofVerifyErrors({
    implemented: match,
    testDescription:
      `Data Integrity (ecdsa-rdfc-2019 verifiers) VC ${vcVersion}`,
    testDataOptions: {
      suiteName: 'ecdsa-rdfc-2019',
      cryptosuite: ecdsaRdfc2019Cryptosuite,
      key,
      testVector: document,
      keyType: 'P-256'
    },
    optionalTests
  });
}
