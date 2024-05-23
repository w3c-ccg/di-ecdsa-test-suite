/*!
 * Copyright 2023 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import {
  checkDataIntegrityProofVerifyErrors
} from 'data-integrity-test-suite-assertion';
import {endpoints} from 'vc-test-suite-implementations';
import {getSuiteConfig} from './test-config.js';

const {tags} = getSuiteConfig('ecdsa-sd-2023');

// only use implementations with `ecdsa-sd-2023` verifiers.
const {match} = endpoints.filterByTag({
  tags: [...tags],
  property: 'verifiers'
});
// options for the DI Verifier Suite
const testDataOptions = {
  suiteName: 'ecdsa-sd-2023',
  keyType: 'P-256',
  mandatoryPointers: ['/issuer'],
  selectivePointers: ['/credentialSubject']
};
await checkDataIntegrityProofVerifyErrors({
  implemented: match,
  isEcdsaTests: true,
  testDescription: 'Data Integrity (ecdsa-sd-2023 verifiers)',
  testDataOptions
});

