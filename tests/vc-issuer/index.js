/*!
 * Copyright 2024 Digital Bazaar, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
import * as base58 from 'base58-universal';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as rdfCanonize from 'rdf-canonize';
import crypto from 'crypto';
import jsonld from 'jsonld';
import {loader} from './documentLoader.js';

const documentLoader = loader.build();
const publicKeyMultibase = 'zDnaekGZTbQBerwcehBSXLqAg6s55hVEBms1zFy89VHXtJSa9';
const secretKeyMultibase = 'z42tqZ5smVag3DtDhjY9YfVwTMyVHW6SCHJi2ZMrD23DGYS3';
const controller = `did:key:${publicKeyMultibase}`;

export function generateProofId() {
  return `urn:uuid:${crypto.randomUUID()}`;
}

const dataIntegrityProof = {
  type: 'DataIntegrityProof',
  cryptosuite: 'ecdsa-rdfc-2019',
  proofPurpose: 'assertionMethod',
  verificationMethod: `${controller}#${publicKeyMultibase}`,
};

// create the keypair to use when signing
const keyPair = await EcdsaMultikey.from({
  '@context': 'https://w3id.org/security/multikey/v1',
  id: `${controller}#${publicKeyMultibase}`,
  type: 'Multikey',
  controller,
  publicKeyMultibase,
  secretKeyMultibase
});

// create the unsigned credential
const unsignedCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: controller,
  credentialSubject: {name: 'Alice'}
};

export async function createVc() {
  return addProof(unsignedCredential);
}

export async function addProof(credential, previousProof = null) {
  const proofSet = credential?.proof || [];
  const unsecuredDocument = structuredClone(credential);
  delete unsecuredDocument.proof;
  const proofOptions = structuredClone(dataIntegrityProof);
  if(previousProof) {
    // const allProofs = [];
    const matchingProofs = proofSet.filter(entry => entry.id === previousProof);
    unsecuredDocument.proof = matchingProofs;
    proofOptions.previousProof = previousProof;
  }

  const securedDocument = structuredClone(unsecuredDocument);
  const proof = await createProof(unsecuredDocument, proofOptions);
  proofSet.push(proof);
  securedDocument.proof = proofSet;

  return securedDocument;
}

export async function createProof(unsecuredDocument, options) {
  // https://www.w3.org/TR/vc-di-ecdsa/#create-proof-ecdsa-rdfc-2019
  options.id = generateProofId();
  const proof = structuredClone(options);

  options['@context'] = unsecuredDocument['@context'];

  const proofConfig = await canonize(options);
  const proofConfigHash =
    crypto.createHash('sha256').update(proofConfig).digest('hex');

  const transformedData = await canonize(unsecuredDocument);
  const transformedDataHash =
    crypto.createHash('sha256').update(transformedData).digest('hex');

  const hashData = proofConfigHash + transformedDataHash;
  const proofbytes = await keyPair.signer().sign(
    {data: Uint8Array.from(Buffer.from(hashData, 'hex'))});

  proof.proofValue = `z${base58.encode(proofbytes)}`;

  return proof;
}

async function canonize(input) {
  const options = {
    algorithm: 'RDFC-1.0',
    base: null,
    documentLoader,
    safe: true,
    skipExpansion: false,
    produceGeneralizedRdf: false,
    rdfDirection: 'i18n-datatype',
    messageDigestAlgorithm: 'SHA-256',
  };
  const dataset = await jsonld.toRDF(input, options);
  delete options.produceGeneralizedRdf;
  options.format = 'application/n-quads';
  return rdfCanonize.canonize(dataset, options);
}
