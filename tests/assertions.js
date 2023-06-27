/*!
 * Copyright 2023 Digital Bazaar, Inc. All Rights Reserved
 */
import {
  multibaseMultikeyHeaderP256, multibaseMultikeyHeaderP384
} from './helpers.js';
import {decode} from 'base58-universal';

// RegExp with bs58 characters in it
const bs58 =
  /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
// assert something is entirely bs58 encoded
export const shouldBeBs58 = s => bs58.test(s);

export const shouldBeMulticodecEncoded = async s => {
  // check if it is multi codec encoded
  if(s.startsWith(multibaseMultikeyHeaderP256)) {
    // zDnaepHgv4AU1btQ8dp6EYbvgJ6M1ovzKnSpXJUPU2hshXLvp
    const bytes = await decode(s.slice(1));
    bytes.length.should.equal(35);
    // bytes example => Uint8Array(35) [
    //   128,  36,   3,  98, 121, 153, 205, 199,
    //    39, 148, 212,  49, 157,  57, 152, 184,
    //    97,  14, 217, 198,  76,  50,  46, 169,
    //    58, 124, 244, 202, 141, 161,  92,  55,
    //   122, 233, 205
    // ]
    // FIXME: convert first two byte prefix to 0x1200 and add assertions
    // the multicodec encoding of a P-256 public key is the two-byte
    // prefix 0x1200 followed by the 33-byte compressed public key data.
  }

  if(s.startsWith(multibaseMultikeyHeaderP384)) {
    const bytes = await decode(s.slice(1));
    bytes.length.should.equal(51);
    // FIXME: convert first two byte prefix to 0x1201 and add assertions
    // the multicodec encoding of a P-384 public key is the two-byte prefix
    // 0x1201 followed by the 49-byte compressed public key data.
  }
};