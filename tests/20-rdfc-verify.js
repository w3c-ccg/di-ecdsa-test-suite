import {
  itMustVerifyValidVC,
  itRejectsInvalidCryptosuite,
} from './assertions.js';
import {defineSuiteConformanceTests} from './suiteTests.js';
import {issueCredentials} from './vc-generator/index.js';

function buildTestVectors(suite, credentials, keyTypes) {
  return issueCredentials({
    credentials: Object.entries(credentials.verify),
    suite,
    keyTypes
  });
}

describe('ecdsa-rdfc-2019 (verify)', async function() {
  await defineSuiteConformanceTests({
    suite: 'ecdsa-rdfc-2019',
    testCategory: 'verifiers',
    buildTestVectorsFn: buildTestVectors,
  }, function(args) {
    itMustVerifyValidVC(args);
    itRejectsInvalidCryptosuite(['ecdsa-rdfc-2019', 'ecdsa-jcs-2019'], args);
  });
});
