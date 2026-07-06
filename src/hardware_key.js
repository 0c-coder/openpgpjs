/**
 * @fileoverview Build a hardware-backed PrivateKey (e.g. OnlyKey) from a public key.
 *
 * openpgp.js will not sign or decrypt unless it holds an *unlocked private key*
 * (it checks `secretKeyPacket.isDecrypted()` first, and throws otherwise — before
 * ever reaching `crypto/signature.js:sign()` / `crypto/crypto.js:publicKeyDecrypt()`
 * where the hardware hooks in `crypto/hardware.js` live).
 *
 * A hardware key has no private material to give (it lives on the device). So this
 * factory produces a stand-in: a PrivateKey built from the device's *real public
 * key* (correct fingerprint / key-id / algorithm) whose secret packets are marked
 * "decrypted" and carry *placeholder* private params. openpgp.js then proceeds into
 * the crypto functions, the registered hardware hook takes over and routes the real
 * operation to the device, and the placeholder params are ignored.
 *
 * This is the openpgp.js equivalent of the placeholder private key the kbpgp fork
 * loads alongside its global `onlykey` hook. 100% host-side — no firmware.
 * @module hardware_key
 * @access public
 */

import PrivateKey from './key/private_key.js';
import PacketList from './packet/packetlist.js';
import SecretKeyPacket from './packet/secret_key.js';
import SecretSubkeyPacket from './packet/secret_subkey.js';
import enums from './enums.ts';

// Minimal placeholder private params per algorithm. The hardware hooks return
// before these are used, so the *values* never matter — only that the expected
// keys exist so nothing destructures `undefined`. (The ECDH/X25519 scalar carries
// a marker so a `d`/`k`-only call site can still tell it's a hardware key.)
function placeholderPrivateParams(algo) {
  const stub = () => new Uint8Array([1]);
  const P = enums.publicKey;
  switch (algo) {
    case P.rsaEncryptSign:
    case P.rsaEncrypt:
    case P.rsaSign:
      return { d: stub(), p: stub(), q: stub(), u: stub() };
    case P.ecdsa:
    case P.ecdh:
      return { d: markHardware(stub()) };
    case P.dsa:
    case P.elgamal:
      return { x: stub() };
    case P.eddsaLegacy:
    case P.ed25519:
    case P.ed448:
      return { seed: stub() };
    case P.x25519:
    case P.x448:
      return { k: markHardware(stub()) };
    default:
      return {};
  }
}

// Tag the raw scalar so a hook that only receives `d`/`k` (elliptic ecdh*.decrypt)
// can still recognise a hardware key if it wants scalar-level routing.
function markHardware(scalar) {
  scalar.isHardwareBacked = true;
  return scalar;
}

// Convert one public-key packet into a "decrypted" hardware secret-key packet,
// copying the public material (so fingerprint / key-id / algorithm are correct).
function toHardwareSecret(pub, SecretPacketClass) {
  const sec = new SecretPacketClass(pub.created);
  sec.version = pub.version;
  sec.created = pub.created;
  sec.algorithm = pub.algorithm;
  sec.publicParams = pub.publicParams;
  sec.fingerprint = pub.fingerprint;
  sec.keyID = pub.keyID;

  sec.isEncrypted = false;          // => isDecrypted() === true : passes the gate
  sec.s2kUsage = 0;
  sec.privateParams = placeholderPrivateParams(pub.algorithm);
  sec.isHardwareBacked = true;      // informational flag for the app / hooks
  return sec;
}

/**
 * Produce a hardware-backed PrivateKey from the device's public key.
 * @param {PublicKey} publicKey - an openpgp `PublicKey` (e.g. from `readKey({ armoredKey })`
 *   of the OnlyKey's exported public key)
 * @returns {PrivateKey} a PrivateKey usable with `openpgp.sign` / `openpgp.decrypt`;
 *   every private-key operation is routed to the device via the hooks in
 *   `crypto/hardware.js` (register them with `setHardwareHooks(...)`).
 */
export function createHardwarePrivateKey(publicKey) {
  const source = publicKey.toPacketList();
  const list = new PacketList();
  for (const packet of source) {
    const tag = packet.constructor.tag;
    if (tag === enums.packet.publicKey) {
      list.push(toHardwareSecret(packet, SecretKeyPacket));
    } else if (tag === enums.packet.publicSubkey) {
      list.push(toHardwareSecret(packet, SecretSubkeyPacket));
    } else {
      list.push(packet); // user IDs, user attributes, signatures — kept as-is
    }
  }
  return new PrivateKey(list);
}

export default createHardwarePrivateKey;
