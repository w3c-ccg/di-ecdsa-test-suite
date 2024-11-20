/*!
 * Copyright 2023 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import * as bs58 from 'base58-universal';
import * as bs64 from 'base64url-universal';
import {createRequire} from 'node:module';
import {klona} from 'klona';
import {v4 as uuidv4} from 'uuid';

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
export const createInitialVc = async ({
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
    console.warn(
      `initial vc creation failed for ${(result || error)?.requestUrl}`,
      error,
      JSON.stringify(data, null, 2)
    );
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
    console.warn(
      `derived vc creation failed for ${(result || error)?.requestUrl}`,
      error,
      JSON.stringify(data, null, 2)
    );
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
