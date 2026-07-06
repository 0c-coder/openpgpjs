/**
 * @fileoverview Optional hardware delegation hooks (e.g. OnlyKey).
 * Mirrors kbpgp's global `onlykey`: when a hook is registered, the corresponding
 * private-key operation is routed to the device instead of using local key
 * material. Every hook may return null/undefined to fall through to the software
 * path, so a fork with hooks registered still works for software keys (inspect
 * `publicKeyParams` to route per key).
 * @module crypto/hardware
 * @access private
 */

const hooks = {
  /**
   * Sign an already-hashed message on the device.
   * @param {module:enums.publicKey} algo
   * @param {module:enums.hash} hashAlgo
   * @param {Uint8Array} hashed - the hashed data to sign (openpgp.js pre-hashes)
   * @param {Object} publicKeyParams - identifies which key (for routing)
   * @returns {Promise<Object|null>} signature params in openpgp.js shape:
   *   rsa*            -> { s }        (big-endian signature bytes)
   *   ecdsa           -> { r, s }     (two Uint8Arrays)
   *   eddsaLegacy     -> { r, s }     (R point, S little-endian)
   *   ed25519/ed448   -> { RS }       (raw native 64/114-byte signature)
   *   or null to use the software path.
   */
  signer: null,

  /**
   * Decrypt an RSA/Elgamal PKESK session key on the device.
   * (ECDH/X25519 are delegated deeper — see `ecdh` — so openpgp.js keeps doing
   *  the KDF + AES key-unwrap.)
   * @param {module:enums.publicKey} algo
   * @param {Object} sessionKeyParams - e.g. { c } for RSA
   * @param {Object} publicKeyParams - identifies which key (for routing)
   * @param {Uint8Array} fingerprint
   * @returns {Promise<Uint8Array|null>} the decrypted session-key bytes, or null.
   */
  decryptor: null,

  /**
   * Compute an ECDH / X25519 / X448 shared secret on the device from the sender's
   * ephemeral public point. Used by both v4 ECDH and v6 X25519/X448 decryption;
   * openpgp.js performs the KDF + unwrap afterwards. This is the same device
   * primitive as the split-custody X-Wing derive (PR #40).
   * @param {module:enums.publicKey} algo - ecdh | x25519 | x448
   * @param {Uint8Array} ephemeralPublicKey - V, the sender's ephemeral point
   * @param {Object} publicKeyParams - identifies which key (for routing)
   * @returns {Promise<Uint8Array|null>} the raw shared secret, or null.
   */
  ecdh: null
};

/** Register one or more hardware hooks. */
export function setHardwareHooks(newHooks = {}) {
  Object.assign(hooks, newHooks);
  return hooks;
}

/** Remove all hardware hooks (revert to pure software). */
export function clearHardwareHooks() {
  hooks.signer = null;
  hooks.decryptor = null;
  hooks.ecdh = null;
}

export default hooks;
