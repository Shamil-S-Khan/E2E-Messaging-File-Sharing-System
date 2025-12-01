// client/src/utils/cryptoUtils.js

const RSA_KEY_ALGORITHM = {
  name: "RSA-OAEP",
  modulusLength: 2048, // Or 3072, as per requirements
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: "SHA-256",
};

const ECDH_KEY_ALGORITHM = {
  name: "ECDH",
  namedCurve: "P-256", // As required by the prompt
};

const AES_GCM_ALGORITHM = {
  name: "AES-GCM",
  length: 256,
};

const PBKDF2_ALGORITHM = {
  name: "PBKDF2",
  // salt should be generated per use
  iterations: 100000,
  hash: "SHA-256",
};

const SIGNATURE_ALGORITHM = {
  name: "RSASSA-PKCS1-v1_5", // For digital signatures (RSA-based)
  hash: "SHA-256",
};

/**
 * Generates an RSA-OAEP key pair for encryption/decryption.
 * @returns {Promise<CryptoKeyPair>}
 */
async function generateRSAKeyPair() {
  return window.crypto.subtle.generateKey(
    RSA_KEY_ALGORITHM,
    true, // extractable
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}

/**
 * Generates an ECDH key pair for key agreement.
 * @returns {Promise<CryptoKeyPair>}
 */
async function generateECDHKeyPair() {
  return window.crypto.subtle.generateKey(
    ECDH_KEY_ALGORITHM,
    true, // extractable
    ["deriveKey", "deriveBits"]
  );
}

/**
 * Exports a CryptoKey to JWK format.
 * @param {CryptoKey} key
 * @returns {Promise<JsonWebKey>}
 */
async function exportKeyToJwk(key) {
  return window.crypto.subtle.exportKey("jwk", key);
}

/**
 * Imports a key from JWK format.
 * @param {JsonWebKey} jwk
 * @param {string} keyAlgorithm 'RSA-OAEP', 'ECDH', or 'AES-GCM'
 * @param {string[]} usages Array of usages (e.g., ['encrypt'], ['decrypt'], ['deriveKey'])
 * @returns {Promise<CryptoKey>}
 */
async function importKeyFromJwk(jwk, keyAlgorithm, usages) {
  let algorithm;
  if (keyAlgorithm === 'RSA-OAEP') {
    algorithm = RSA_KEY_ALGORITHM;
    // Expect jwk.kty === 'RSA'
    if (jwk.kty !== 'RSA') throw new Error('The JWK "kty" member was not "RSA"');
  } else if (keyAlgorithm === 'ECDH') {
    algorithm = ECDH_KEY_ALGORITHM;
    // Expect jwk.kty === 'EC'
    if (jwk.kty !== 'EC') throw new Error('The JWK "kty" member was not "EC"');
  } else if (keyAlgorithm === 'AES-GCM') {
    algorithm = AES_GCM_ALGORITHM;
    // Expect jwk.kty === 'oct'
    if (jwk.kty !== 'oct') throw new Error('The JWK "kty" member was not "oct"');
  } else {
    throw new Error(`Unsupported key algorithm: ${keyAlgorithm}`);
  }
  // Remove key_ops for compatibility
  const { key_ops, ...cleanJwk } = jwk;
  return window.crypto.subtle.importKey(
    "jwk",
    cleanJwk,
    algorithm,
    true,
    usages
  );
}

/**
 * Exports a public CryptoKey to SPKI (PEM) format, then converts to base64.
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>} Base64 encoded SPKI string.
 */
async function exportPublicKeyToSpkiBase64(publicKey) {
  const spkiBuffer = await window.crypto.subtle.exportKey("spki", publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
}

/**
 * Imports a public key from SPKI (Base64) format for signature verification.
 * Note: We strictly import as RSASSA-PKCS1-v1_5 because the usage is 'verify'.
 * @param {string} spkiBase64
 * @returns {Promise<CryptoKey>}
 */
async function importPublicKeyFromSpkiBase64(spkiBase64) {
  const spkiBuffer = Uint8Array.from(atob(spkiBase64), c => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    "spki",
    spkiBuffer,
    SIGNATURE_ALGORITHM, // Use RSASSA-PKCS1-v1_5 for verification
    true, // extractable
    ["verify"] // For signature verification
  );
}

/**
 * Creates a digital signature for data using the provided RSA private key.
 * @param {CryptoKey} privateKey RSA private key for signing.
 * @param {Uint8Array} data Data to be signed.
 * @returns {Promise<string>} Base64 encoded signature.
 */
async function signData(privateKey, data) {
  const signatureBuffer = await window.crypto.subtle.sign(
    SIGNATURE_ALGORITHM,
    privateKey,
    data
  );
  return btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
}

/**
 * Verifies a digital signature using the provided RSA public key.
 * @param {CryptoKey} publicKey RSA public key for verification.
 * @param {string} signatureBase64 Base64 encoded signature.
 * @param {Uint8Array} data Original data that was signed.
 * @returns {Promise<boolean>} True if the signature is valid, false otherwise.
 */
async function verifySignature(publicKey, signatureBase64, data) {
  const signatureBuffer = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
  return window.crypto.subtle.verify(
    SIGNATURE_ALGORITHM,
    publicKey,
    signatureBuffer,
    data
  );
}

/**
 * Derives an AES-GCM key from a password using PBKDF2.
 * @param {string} password
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKeyFromPassword(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ALGORITHM.iterations,
      hash: PBKDF2_ALGORITHM.hash,
    },
    keyMaterial,
    AES_GCM_ALGORITHM,
    true, // extractable
    ["encrypt", "decrypt"]
  );
}

/**
 * Derives a shared secret (bits) using ECDH.
 * @param {CryptoKey} privateKey Our ECDH private key.
 * @param {CryptoKey} publicKey Their ECDH public key.
 * @returns {Promise<ArrayBuffer>} The shared secret bits.
 */
async function deriveSharedSecret(privateKey, publicKey) {
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    256 // Derive 256 bits
  );

  // DEBUG: Log shared secret bits
  const view = new Uint8Array(bits);
  console.log("[DEBUG] Shared Secret Bits:", Array.from(view).slice(0, 5)); // Log first 5 bytes

  return bits;
}

/**
 * Derives a final session key using SHA-256 from the shared secret bits and nonces.
 * @param {ArrayBuffer} sharedSecretBits The shared secret bits from ECDH.
 * @param {Uint8Array} nonceA Nonce from Alice.
 * @param {Uint8Array} nonceB Nonce from Bob.
 * @returns {Promise<CryptoKey>} The final AES-256-GCM session key.
 */
async function deriveSessionKey(sharedSecretBits, nonceA, nonceB) {
  const combinedNonces = new Uint8Array(nonceA.length + nonceB.length);
  combinedNonces.set(nonceA, 0);
  combinedNonces.set(nonceB, nonceA.length);

  // Combine Shared Secret Bits + Nonces
  const keyMaterial = new Uint8Array(sharedSecretBits.byteLength + combinedNonces.byteLength);
  keyMaterial.set(new Uint8Array(sharedSecretBits), 0);
  keyMaterial.set(combinedNonces, sharedSecretBits.byteLength);

  // Hash to get uniform key material
  const hashedKeyMaterial = await window.crypto.subtle.digest("SHA-256", keyMaterial);

  // Import the hashed material as an AES key
  const sessionKey = await window.crypto.subtle.importKey(
    "raw",
    hashedKeyMaterial,
    AES_GCM_ALGORITHM,
    true,
    ["encrypt", "decrypt"]
  );

  // DEBUG: Export and log the key to check for matches
  const exported = await window.crypto.subtle.exportKey("jwk", sessionKey);
  console.log("[DEBUG] Derived Session Key (k):", exported.k);

  return sessionKey;
}


/**
 * Encrypts data using AES-GCM.
 * @param {CryptoKey} key
 * @param {Uint8Array} data
 * @returns {Promise<{iv: string, ciphertext: string, tag: string}>} iv, ciphertext, and authentication tag in base64.
 */
async function encryptWithAesGcm(key, data) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for AES-GCM IV

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    data
  );

  const tagLength = 16; // AES-GCM tag is 16 bytes (128 bits)
  const ciphertext = new Uint8Array(encryptedBuffer, 0, encryptedBuffer.byteLength - tagLength);
  const tag = new Uint8Array(encryptedBuffer, encryptedBuffer.byteLength - tagLength, tagLength);

  // Helper function to convert Uint8Array to base64 without stack overflow
  const arrayToBase64 = (array) => {
    const CHUNK_SIZE = 0x8000; // 32KB chunks to avoid stack overflow
    let binary = '';
    for (let i = 0; i < array.length; i += CHUNK_SIZE) {
      const chunk = array.subarray(i, Math.min(i + CHUNK_SIZE, array.length));
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  };

  return {
    iv: arrayToBase64(iv),
    ciphertext: arrayToBase64(ciphertext),
    tag: arrayToBase64(tag),
  };
}

/**
 * Decrypts data using AES-GCM.
 * @param {CryptoKey} key
 * @param {string} ivBase64
 * @param {string} ciphertextBase64
 * @param {string} tagBase64
 * @returns {Promise<Uint8Array>} decrypted data.
 */
async function decryptWithAesGcm(key, ivBase64, ciphertextBase64, tagBase64) {
  const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));
  const tag = Uint8Array.from(atob(tagBase64), c => c.charCodeAt(0));

  // Combine ciphertext and tag for decryption
  const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.byteLength);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    combined
  );

  return new Uint8Array(decryptedBuffer);
}

/**
 * Hashes data using SHA-256.
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>} The SHA-256 hash.
 */
async function sha256(data) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Creates a Message Authentication Code (MAC) using the session key.
 * For AES-GCM, the MAC is effectively the authentication tag produced during encryption
 * if the data being MAC'd is treated as AAD or part of the encrypted payload.
 *
 * For a standalone MAC (as per the prompt's request for MAC(SessionKey, "CONFIRMED")),
 * we'll use HMAC with the session key. Since session key is AES-GCM, we need to convert it
 * to a raw key or derive a separate HMAC key from it.
 * Given "MAC(SessionKey, ...)" it implies directly using the session key.
 *
 * To use the AES-GCM session key as an HMAC key, we need to export it as raw and import it for HMAC.
 * @param {CryptoKey} sessionKey The AES-GCM session key.
 * @param {string} message The message to MAC (e.g., "CONFIRMED").
 * @returns {Promise<string>} Base64 encoded MAC.
 */
async function createMac(sessionKey, message) {
  // Export the AES-GCM session key as raw bytes
  const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);

  // Import it as an HMAC key
  const hmacKey = await window.crypto.subtle.importKey(
    "raw",
    rawSessionKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const encoder = new TextEncoder();
  const dataToMac = encoder.encode(message);

  const macBuffer = await window.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    dataToMac
  );

  return btoa(String.fromCharCode(...new Uint8Array(macBuffer)));
}

/**
 * Verifies a Message Authentication Code (MAC).
 * @param {CryptoKey} sessionKey The AES-GCM session key.
 * @param {string} macBase64 Base64 encoded MAC to verify.
 * @param {string} message The original message (e.g., "CONFIRMED").
 * @returns {Promise<boolean>} True if MAC is valid, false otherwise.
 */
async function verifyMac(sessionKey, macBase64, message) {
  // Export the AES-GCM session key as raw bytes
  const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);

  // Import it as an HMAC key
  const hmacKey = await window.crypto.subtle.importKey(
    "raw",
    rawSessionKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const encoder = new TextEncoder();
  const dataToMac = encoder.encode(message);
  const macBuffer = Uint8Array.from(atob(macBase64), c => c.charCodeAt(0));

  return window.crypto.subtle.verify(
    "HMAC",
    hmacKey,
    macBuffer,
    dataToMac
  );
}


export {
  generateRSAKeyPair,
  generateECDHKeyPair,
  exportKeyToJwk,
  exportPublicKeyToSpkiBase64,
  importKeyFromJwk,
  importPublicKeyFromSpkiBase64,
  signData,
  verifySignature,
  deriveKeyFromPassword,
  deriveSharedSecret,
  deriveSessionKey,
  encryptWithAesGcm,
  decryptWithAesGcm,
  sha256,
  createMac,
  verifyMac,
};