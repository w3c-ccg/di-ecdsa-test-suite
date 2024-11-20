/*!
 * Copyright 2023-2024 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import {createInitialVc, endpointCheck} from './helpers.js';
import {
  shouldBeBs58,
  shouldBeMulticodecEncoded,
  shouldHaveByteLength,
  verificationSuccess
} from './assertions.js';
import {cryptosuite} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {documentLoader} from './documentLoader.js';
import {endpoints} from 'vc-test-suite-implementations';
import {expect} from 'chai';
import {getSuiteConfig} from './test-config.js';
import {localVerifier} from './vc-verifier/index.js';

const {
  tags,
  credentials,
  vectors,
  proofLengths
} = getSuiteConfig('ecdsa-rdfc-2019');
const {match} = endpoints.filterByTag({
  tags: [...tags],
  property: 'issuers'
});

const verifier = localVerifier({cryptosuite});

describe('ecdsa-rdfc-2019 (create)', function() {
  for(const vcVersion of vectors.vcTypes) {
    describe(`ecdsa-rdfc-2019 (issuers) VC ${vcVersion}`, function() {
      this.matrix = true;
      this.report = true;
      this.implemented = [];
      this.rowLabel = 'Test Name';
      this.columnLabel = 'Implementation';
      for(const [name, {endpoints: issuers}] of match) {
        // test for each support key type
        for(const keyType of vectors.keyTypes) {
        // loop through each issuer in suite
          for(const issuer of issuers) {
            // does the endpoint support this test?
            if(!endpointCheck({endpoint: issuer, keyType, vcVersion})) {
              continue;
            }
            // add implementer name and keyType to test report
            this.implemented.push(`${name}: ${keyType}`);
            describe(`${name}: ${keyType}`, function() {
              let issuedVc;
              let proofs;
              const verificationMethodDocuments = [];
              before(async function() {
                issuedVc = await createInitialVc({
                  issuer,
                  vc: credentials.create[vcVersion].document,
                  vcVersion
                });
                // VCs can have multiple proofs so account for that
                proofs = Array.isArray(issuedVc?.proof) ? issuedVc.proof :
                  [issuedVc?.proof];
                const verificationMethods = proofs.map(
                  proof => proof.verificationMethod);
                for(const verificationMethod of verificationMethods) {
                  const verificationMethodDocument = await documentLoader({
                    url: verificationMethod
                  });
                  verificationMethodDocuments.push(verificationMethodDocument);
                }
              });
              /*
              @link https://w3c.github.io/vc-di-ecdsa/
              #verify-derived-proof-ecdsa-sd-2023:~:text=
              The%20type%20property%20MUST%20be%20DataIntegrityProof
              */
              it('The (proof) type property MUST be DataIntegrityProof.',
                function() {
                  this.test.cell = {
                    columnId: `${name}: ${keyType}`, rowId: this.test.title
                  };
                  proofs.map(p => p?.type).should.contain(
                    'DataIntegrityProof',
                    'Expected at least one proof to have type ' +
                    'DataIntegrityProof');
                });
              /*
               @link https://w3c.github.io/vc-di-ecdsa/
               #verify-derived-proof-ecdsa-sd-2023:~:text=
               The%20cryptosuite%20property%20MUST%20be%20ecdsa%2Drdfc%2D2019%
               2C%20ecdsa%2Djcs%2D2019%2C%20or%20ecdsa%2Dsd%2D2023.
               */
              it('The cryptosuite property of the proof MUST be ' +
              'ecdsa-rdfc-2019 or ecdsa-jcs-2019.', function() {
                this.test.cell = {
                  columnId: `${name}: ${keyType}`, rowId: this.test.title
                };
                const cryptosuite = ['ecdsa-rdfc-2019', 'ecdsa-jcs-2019'];
                expect(
                  proofs.map(proof => proof?.cryptosuite),
                  'Expected at least one proof to have ' +
                '"cryptosuite" property "ecdsa-rdfc-2019" or "ecdsa-jcs-2019".')
                  .to.contain.oneOf(cryptosuite);
              });
              it('the signature value (proofValue) MUST be expressed ' +
              'according to section 7 of [RFC4754] (sometimes referred to ' +
              'as the IEEE P1363 format) and encoded according to the ' +
              'specific cryptosuite proof generation algorithm.',
              async function() {
                this.test.cell = {
                  columnId: `${name}: ${keyType}`, rowId: this.test.title
                };
                const _proof = proofs.find(p =>
                  p?.cryptosuite === 'ecdsa-rdfc-2019');
                expect(
                  _proof,
                  `Expected VC from issuer ${name} to have an ' +
                  '"ecdsa-rdfc-2019" proof`).to.exist;
                expect(
                  _proof.proofValue,
                  `Expected VC from issuer ${name} to have a ' +
                  '"proof.proofValue"`
                ).to.exist;
                expect(
                  _proof.proofValue,
                  `Expected VC "proof.proofValue" from issuer ${name} to be ` +
                  'a string.'
                ).to.be.a.string;
                // now test the encoding which is bs58 for this suite
                expect(
                  shouldBeBs58(_proof.proofValue),
                  'Expected "proof.proofValue" to be bs58 encoded.'
                ).to.be.true;
                // proofBytes will be exactly 64 bytes in size for a P-256 key,
                // and 96 bytes in size for a P-384 key.
                const expectedLength = proofLengths[keyType];
                await shouldHaveByteLength(_proof.proofValue, expectedLength);
              });
              it('The "proof" MUST verify with a conformant verifier.',
                async function() {
                  this.test.cell = {
                    columnId: `${name}: ${keyType}`, rowId: this.test.title
                  };
                  await verificationSuccess({
                    credential: issuedVc,
                    verifier
                  });
                });
              it('The "proof.proofPurpose" field MUST match the verification ' +
                'relationship expressed by the verification method controller.',
              async function() {
                this.test.cell = {
                  columnId: `${name}: ${keyType}`, rowId: this.test.title
                };
                verificationMethodDocuments.should.not.eql([], 'Expected ' +
                  'at least one "verificationMethodDocument".');
                verificationMethodDocuments.some(
                  verificationMethodDocument =>
                    verificationMethodDocument?.type === 'Multikey'
                ).should.equal(true, 'Expected at least one proof to have ' +
                  '"type" property value "Multikey".'
                );
                const controllerDocuments = [];
                for(const verificationMethodDocument of
                  verificationMethodDocuments) {
                  const controllerDocument = await documentLoader({
                    url: verificationMethodDocument.controller
                  });
                  controllerDocuments.push(controllerDocument);
                }
                proofs.some(
                  proof => controllerDocuments.some(controllerDocument =>
                    controllerDocument.hasOwnProperty(proof.proofPurpose))
                ).should.equal(true, 'Expected "proof.proofPurpose" field ' +
                  'to match the verification method controller.'
                );
              });
              it('Dereferencing "verificationMethod" MUST result in an ' +
              'object containing a type property with "Multikey" value.',
              async function() {
                this.test.cell = {
                  columnId: `${name}: ${keyType}`, rowId: this.test.title
                };
                verificationMethodDocuments.should.not.eql([], 'Expected ' +
                  'at least one "verificationMethodDocument".');
                verificationMethodDocuments.some(
                  verificationMethodDocument =>
                    verificationMethodDocument?.type === 'Multikey'
                ).should.equal(true, 'Expected at least one proof to have ' +
                  '"type" property value "Multikey".'
                );
              });
              it('The "publicKeyMultibase" property of the verification ' +
                'method MUST be public key encoded according to MULTICODEC ' +
                'and formatted according to MULTIBASE.', async function() {
                this.test.cell = {
                  columnId: `${name}: ${keyType}`, rowId: this.test.title
                };
                verificationMethodDocuments.should.not.eql([], 'Expected ' +
                  '"verificationMethodDocuments" to not be empty.');
                verificationMethodDocuments.some(
                  verificationMethodDocument => {
                    const multibase = 'z';
                    const {publicKeyMultibase} = verificationMethodDocument;
                    return publicKeyMultibase.startsWith(multibase) &&
                      shouldBeBs58(publicKeyMultibase) &&
                      shouldBeMulticodecEncoded(publicKeyMultibase);
                  }
                ).should.equal(true, 'Expected at "publicKeyMultibase" to ' +
                  'be MULTIBASE formatted and MULTICODEC encoded.');
              });
            });
          }
        }
      }
    });
  }
});
