/*!
 * Copyright 2024 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import {
  addProof,
  createVc,
  generateProofId
} from './vc-issuer/index.js';
import {
  setupReportableTestSuite,
  setupRow,
  verifyError,
  verifySuccess
} from './helpers.js';
import {endpoints} from 'vc-test-suite-implementations';

const cryptosuites = [
  'ecdsa-rdfc-2019',
];

const {match: issuers} = endpoints.filterByTag({
  tags: cryptosuites,
  property: 'issuers'
});
issuers;

const {match: verifiers} = endpoints.filterByTag({
  tags: cryptosuites,
  property: 'verifiers'
});

describe('Proof Chains', function() {
  setupReportableTestSuite(this);
  for(const [columnId, {endpoints}] of verifiers) {
    describe(columnId, function() {
      const [verifier] = endpoints;
      let issuedCredential;
      let issuedProofSet;
      let issuedProofChain;
      let negativeFixture;
      before(async function() {
        issuedCredential = await createVc();
        issuedProofChain = await addProof(
          structuredClone(issuedCredential), issuedCredential.proof[0].id);
        issuedProofSet = await addProof(
          structuredClone(issuedCredential));
        issuedProofSet;
      });
      beforeEach(setupRow);
      it('If a proof with id value equal to the value of previousProof ' +
        'does not exist in allProofs, an error MUST be raised and SHOULD ' +
        'convey an error type of PROOF_VERIFICATION_ERROR.',
      async function() {
        this.test.link = 'https://www.w3.org/TR/vc-data-integrity/#verify-proof-sets-and-chains';
        await verifySuccess(verifier, issuedProofChain);

        negativeFixture = structuredClone(issuedProofChain);
        negativeFixture.proof[1].id = generateProofId();
        await verifyError(verifier, negativeFixture);
      });
      it('If any element of previousProof list has an id attribute ' +
        'value that does not match the id attribute value of any ' +
        'element of allProofs, an error MUST be raised and SHOULD ' +
        'convey an error type of PROOF_VERIFICATION_ERROR.',
      async function() {
        this.test.link = 'https://www.w3.org/TR/vc-data-integrity/#verify-proof-sets-and-chains';
        await verifySuccess(verifier, issuedProofChain);

        negativeFixture = structuredClone(issuedProofChain);
        negativeFixture.proof[1].id = generateProofId();
        await verifyError(verifier, negativeFixture);
      });
    });
  }
});
