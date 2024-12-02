/*!
 * Copyright 2023 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import * as bs58 from 'base58-universal';
import * as bs64 from 'base64url-universal';
import * as didKey from '@digitalbazaar/did-method-key';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {bases} from 'multiformats/basics';
import {CachedResolver} from '@digitalbazaar/did-io';
import cbor from 'cbor';
import chai from 'chai';
import {createRequire} from 'node:module';
import {contexts as credContexts} from '@digitalbazaar/credentials-context';
import {expect} from 'chai';
import {isUtf8} from 'node:buffer';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';
import {klona} from 'klona';
import {readFileSync} from 'fs';
import {v4 as uuidv4} from 'uuid';

const should = chai.should();

export const require = createRequire(import.meta.url);

// takes a multibase string starting with z lops the z off
// and gets the bytes
export const getBs58Bytes = async s => bs58.decode(s.slice(1));
export const getBs64UrlBytes = async s => bs64.decode(s.slice(1));

// Javascript's default ISO timestamp contains milliseconds.
// This lops off the MS part of the UTC RFC3339 TimeStamp and replaces
// it with a terminal Z.
export const ISOTimeStamp = ({date = new Date()} = {}) => {
  return date.toISOString().replace(/\.\d+Z$/, 'Z');
};

/**
 * Creates an initial VC.
 *
 * @param {object} options - Options to use.
 * @param {object} options.issuer - An endpoint with a post method.
 * @param {object} options.vc - The credential to be issued.
 * @param {Array<string>} [options.mandatoryPointers] - An optional
 *   array of mandatory pointers.
 * @param {string} options.vcVersion - The version of the VC.
 *
 * @returns {Promise<object>} The resulting issuance result.
 */

export const config = JSON.parse(readFileSync('./config/runner.json'));

export const secureCredential = async ({
  issuer,
  vc,
  mandatoryPointers,
  vcVersion
}) => {
  const {settings: {id: issuerId, options = {}}} = issuer;
  const credential = klona(vc);
  credential.id = `urn:uuid:${uuidv4()}`;
  credential.issuer = issuerId;
  const vcNumber = Number(vcVersion);
  if(vcNumber >= 1 && vcNumber < 2.0) {
    credential.issuanceDate = ISOTimeStamp();
  }
  const body = {credential, options};
  // if there are mandatoryPointers for sd tests add them
  if(Array.isArray(mandatoryPointers)) {
    options.mandatoryPointers = mandatoryPointers;
  }
  const {data, result, error} = await issuer.post({json: body});
  if(!result || !result.ok) {
    // console.warn(
    //   `initial vc creation failed for ${(result || error)?.requestUrl}`,
    //   error,
    //   JSON.stringify(data, null, 2)
    // );
    return null;
  }
  return data;
};

export const createDisclosedVc = async ({
  selectivePointers = [], signedCredential, vcHolder
}) => {
  const {data, result, error} = await vcHolder.post({
    json: {
      options: {
        selectivePointers
      },
      verifiableCredential: signedCredential
    }
  });
  if(!result || !result.ok) {
    // console.warn(
    //   `derived vc creation failed for ${(result || error)?.requestUrl}`,
    //   error,
    //   JSON.stringify(data, null, 2)
    // );
  }
  return {disclosedCredential: data};
};

export const endpointCheck = ({endpoint, vcVersion, keyType}) => {
  const {
    supportedEcdsaKeyTypes,
    // assume support for vc 1.1
    supports = {vc: ['1.1']}
  } = endpoint.settings;
  // if an issuer does not support the current keyType skip it
  const keyTypes = supportedEcdsaKeyTypes || supports?.keyTypes;
  if(keyType && !keyTypes?.includes(keyType)) {
    return false;
  }
  // check to make sure the issuer supports the vc type
  if(!supports?.vc?.includes(vcVersion)) {
    return false;
  }
  return true;
};

/**
 * Filters verifiers using supports.vc and tags explicitly.
 * Requires that function is bound to vcDefault, vcVersion, and tags.
 *
 * @example filterVerifiers.bind({
 *   tags: ['foo'],
 *   vc: {
 *     default: '1.1',
 *     version: '2.0'
 *   }
 * })
 *
 * @param {object} options - Options to use.
 * @param {object} options.implementation - An implementation.
 *
 * @returns {Array<object>} An array of filtered endpoints.
 */
export function filterVerifiers({implementation}) {
  const endpoints = implementation.verifiers;
  if(undefined === endpoints) {
    return [];
  }
  // the filter function expects an array to be returned
  return endpoints.filter(e => {
    // we want only endpoints that match every tag
    // this.tags should be provided via .bind
    if(this.tags.every(tag => e.tags.has(tag))) {
      // only return endpoints with the vcVersion support
      // this.vc.default should be provided via .bind
      const {supports = {vc: [this.vc.default]}} = e?.settings;
      // this.vc.version should be provided via .bind
      return supports?.vc?.includes(this.vc.version);
    }
    return false;
  });
}

export const SUPPORTED_BASE58_ECDSA_MULTIKEY_HEADERS = new Map([
  ['P-256', 'zDna'],
  ['P-384', 'z82L'],
  ['Ed25519', 'z6Mk']
]);

export const multibaseMultikeyHeaderP256 =
  SUPPORTED_BASE58_ECDSA_MULTIKEY_HEADERS.get('P-256');

export const multibaseMultikeyHeaderP384 =
  SUPPORTED_BASE58_ECDSA_MULTIKEY_HEADERS.get('P-384');

export const multibaseMultikeyHeaderEd25519 =
  SUPPORTED_BASE58_ECDSA_MULTIKEY_HEADERS.get('Ed25519');

/**
 * Builds a result cell for the test reporter with the expected parameters.
 *
 * This is used to annotate the test results with the implementation name and
 * test name.
 *
 * @param {object} object - The object to use for building the result cell.
 * @param {string} object.name - The name of the implementation.
 * @param {string} object.keyType - The `keyType` being tested (e.g., `P-256`).
 * @param {string} object.testTitle - The title of the test.
 * @returns {object} The result cell object.
 */
export const buildResultCell = ({name, keyType, testTitle}) => ({
  columnId: `${name}: ${keyType}`, rowId: testTitle
});

function getMochaTestDefinitionFromContext(testContext) {
  if('currentTest' in testContext) {
    // Test when called from a `beforeEach` or `afterEach` hook
    return testContext.currentTest;
  }

  if('test' in testContext) {
    // Test when called from a test function directly
    return testContext.test;
  }

  throw new Error('Could not find test definition in test context');
}

export function annotateReportableTest(testContext, {
  implementationName, keyType
}) {
  // The precise test definition object depends on the
  // context in which this helper is called.
  const def = getMochaTestDefinitionFromContext(testContext);

  def.cell = buildResultCell({
    name: implementationName,
    keyType,
    testTitle: def.title
  });
}

export function getColumnNameForTestCategory(testCategory) {
  switch(testCategory) {
    case 'verifiers':
      return 'Verifier';
    case 'issuers':
      return 'Issuer';
    default:
      throw new Error('testCategory must be "verifiers" or "issuers"');
  }
}

export function setupReportableTestSuite(runnerContext, name) {
  runnerContext.matrix = true;
  runnerContext.report = true;
  runnerContext.rowLabel = 'Test Name';
  runnerContext.columnLabel = name;

  runnerContext.implemented = [];
}

export function isValidUtf8(string) {
  const textEncoder = new TextEncoder();
  const uint8Array = textEncoder.encode(string);
  if(!isUtf8(uint8Array)) {
    return false;
  } else {
    return true;
  }
}

export function isValidDatetime(dateString) {
  return !isNaN(Date.parse(dateString));
}

export function getProofs(issuedVc) {
  // if the implementation failed to issue a VC or to sign the VC,
  // return an empty array
  if(!issuedVc?.proof) {
    return [];
  }
  const proofs = Array.isArray(issuedVc?.proof) ?
    issuedVc.proof : [issuedVc?.proof];
  return proofs;
}

export function generateCredential(version = 2) {
  let credential = {
    type: ['VerifiableCredential'],
    id: `urn:uuid:${uuidv4()}`,
    credentialSubject: {id: 'did:example:alice'}
  };
  if(version === 1) {
    // add v1.1 context and issuanceDate
    credential = Object.assign({}, {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/data-integrity/v2'
      ],
      issuanceDate: ISOTimeStamp()
    }, credential);
  } else if(version === 2) {
    // add v2 context
    credential = Object.assign({}, {
      '@context': [
        'https://www.w3.org/ns/credentials/v2'
      ]
    }, credential);
    credential.credentialSubject.name = 'Alice';
  } else {
    return null;
  }
  return credential;
}

export function setupRow() {
  // append test meta data to the it/test this.
  this.currentTest.cell = {
    columnId: this.currentTest.parent.title,
    rowId: this.currentTest.title
  };
}

export function proofExists(securedCredential) {
  should.exist(securedCredential,
    'Expected issuer to have issued a credential.');
  const proofs = getProofs(securedCredential);
  should.exist(proofs,
    'Expected credential to have a proof.');
  proofs.length.should.be.gte(1,
    'Expected credential to have at least one proof.');
  return proofs[0];
}

export async function verifySuccess(verifier, securedCredential) {
  const body = {
    verifiableCredential: securedCredential
  };
  const response = await verifier.post({json: body});
  should.exist(response.result, 'Expected a result from verifier.');
}

export async function verifyError(verifier, securedCredential) {
  const body = {
    verifiableCredential: securedCredential
  };
  const response = await verifier.post({json: body});
  should.exist(response.error, 'Expected an error from verifier.');
}

export async function multikeyFromVerificationMethod(
  verificationMethod, keyType) {
  const cachedResolver = new CachedResolver();
  const jdl = new JsonLdDocumentLoader();
  jdl.addDocuments({documents: credContexts});
  jdl.setDidResolver(cachedResolver);
  const didKeyDriverMultikey = didKey.driver();
  const prefixes = {
    Ed25519: 'z6Mk',
    'P-256': 'zDna',
    'P-384': 'z82L'
  };
  try {
    didKeyDriverMultikey.use({
      multibaseMultikeyHeader: prefixes[keyType],
      fromMultibase: EcdsaMultikey.from
    });
    cachedResolver.use(didKeyDriverMultikey);
    const response = await jdl.documentLoader(verificationMethod);
    return response.document.publicKeyMultibase;
  } catch(error) {
    // Do nothing on error
  }
  return null;
}

export async function inspectSdBaseProofValue(proof) {
  const proofValue = proof.proofValue;
  expect(proof.proofValue.startsWith('u')).to.be.true;
  const cborProof = bases.base64url.decode(proofValue);
  const decodedProof = await cbor.decodeFirst(cborProof, (error, obj) => {
    return obj;
  });
  const decodedProofValues = decodedProof.value;
  decodedProofValues.length.should.equal(5,
    'Expected decoded proof value to be of length 5.'
  );
  return {
    baseSignature: decodedProofValues[0],
    publicKey: decodedProofValues[1],
    hmacKey: decodedProofValues[2],
    signatures: decodedProofValues[3],
    mandatoryPointers: decodedProofValues[4]
  };
}

export async function inspectSdDerivedProofValue(proof) {
  const proofValue = proof.proofValue;
  expect(proof.proofValue.startsWith('u')).to.be.true;
  const cborProof = bases.base64url.decode(proofValue);
  const decodedProof = await cbor.decodeFirst(cborProof, (error, obj) => {
    return obj;
  });
  const decodedProofValues = decodedProof.value;
  decodedProofValues.length.should.equal(5,
    'Expected decoded proof value to be of length 5.'
  );
  return {
    baseSignature: decodedProofValues[0],
    publicKey: decodedProofValues[1],
    signatures: decodedProofValues[2],
    labelMap: decodedProofValues[3],
    mandatoryIndexes: decodedProofValues[4]
  };
}

export async function encodeSdBaseProofValue(decodedProof) {
  const cborProof = await cbor.encode(decodedProof);
  const proofValue = bases.base64url.encode(cborProof);
  return proofValue;
}

export async function encodeSdDerivedProofValue(decodedProof) {
  const cborProof = await cbor.encode(decodedProof);
  const proofValue = bases.base64url.encode(cborProof);
  return proofValue;
}
