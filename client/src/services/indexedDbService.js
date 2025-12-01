import { deriveKeyFromPassword, encryptWithAesGcm, decryptWithAesGcm } from '../utils/cryptoUtils';

const DB_NAME = 'SecureMessagingDB';
const DB_VERSION = 2; // Incremented to add sessionKeys object store
const STORE_NAME = 'privateKeys';

let db = null;

async function openDb() {
  return new Promise((resolve, reject) => {
    if (db) {
      resolve(db);
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = (event) => {
      console.error('IndexedDB error:', event.target.errorCode);
      reject(event.target.errorCode);
    };

    request.onsuccess = (event) => {
      db = event.target.result;
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      const upgradeDb = event.target.result;
      if (!upgradeDb.objectStoreNames.contains(STORE_NAME)) {
        upgradeDb.createObjectStore(STORE_NAME, { keyPath: 'userId' });
      }
      if (!upgradeDb.objectStoreNames.contains('sessionKeys')) {
        upgradeDb.createObjectStore('sessionKeys', { keyPath: 'peerId' });
      }
    };
  });
}

/**
 * Stores an encrypted private key in IndexedDB.
 * The private key (JWK) is encrypted using an AES key derived from the user's password.
 * @param {string} userId
 * @param {JsonWebKey} privateKeyJwk The private key in JWK format.
 * @param {string} password The user's password used to derive the encryption key.
 * @returns {Promise<void>}
 */
async function storeEncryptedPrivateKey(userId, privateKeyJwk, password) {
  // 1. Perform all heavy async crypto operations FIRST
  const encoder = new TextEncoder();
  const privateKeyData = encoder.encode(JSON.stringify(privateKeyJwk));

  // Generate a unique salt for PBKDF2 for this user's private key encryption
  const salt = window.crypto.getRandomValues(new Uint8Array(16));

  const derivedKey = await deriveKeyFromPassword(password, salt);

  // Updated in Step 3: encryptWithAesGcm returns { iv, ciphertext, tag }
  const { iv, ciphertext, tag } = await encryptWithAesGcm(derivedKey, privateKeyData);

  const dataToStore = {
    userId: userId,
    encryptedPrivateKey: ciphertext,
    iv: iv,
    tag: tag, // Store the authentication tag
    salt: btoa(String.fromCharCode(...salt)), // Store salt in base64
  };

  // 2. THEN open the DB and start the transaction.
  const database = await openDb();
  const transaction = database.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  await new Promise((resolve, reject) => {
    const request = store.put(dataToStore);
    request.onsuccess = () => resolve();
    request.onerror = (event) => reject(event.target.error);
  });
}

/**
 * Retrieves and decrypts the private key from IndexedDB.
 * @param {string} userId
 * @param {string} password The user's password used to derive the decryption key.
 * @returns {Promise<JsonWebKey>} The decrypted private key in JWK format.
 */
async function getDecryptedPrivateKey(userId, password) {
  const database = await openDb();
  const transaction = database.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.get(userId);
    request.onsuccess = async (event) => {
      const data = event.target.result;
      if (!data) {
        reject(new Error('Private key not found for this user.'));
        return;
      }

      // Ensure all required fields are present
      if (!data.iv || !data.encryptedPrivateKey || !data.tag || !data.salt) {
        reject(new Error('Corrupted key data in storage (missing IV, Tag, or Salt).'));
        return;
      }

      try {
        const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
        const derivedKey = await deriveKeyFromPassword(password, salt);

        // Pass the tag to the decryption function
        const decryptedDataBuffer = await decryptWithAesGcm(derivedKey, data.iv, data.encryptedPrivateKey, data.tag);

        const decoder = new TextDecoder();
        const privateKeyJwk = JSON.parse(decoder.decode(decryptedDataBuffer));
        resolve(privateKeyJwk);
      } catch (err) {
        console.error("Decryption failed:", err);
        reject(err);
      }
    };
    request.onerror = (event) => reject(event.target.error);
  });
}

/**
 * @param {string} peerId The ID of the peer this session key is for.
 * @param {JsonWebKey} sessionKeyJwk The session key in JWK format.
 * @param {string} password The user's password used to derive the encryption key.
 * @returns {Promise<void>}
 */
async function storeEncryptedSessionKey(peerId, sessionKeyJwk, password) {
  const encoder = new TextEncoder();
  const sessionKeyData = encoder.encode(JSON.stringify(sessionKeyJwk));

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const derivedKey = await deriveKeyFromPassword(password, salt);

  const { iv, ciphertext, tag } = await encryptWithAesGcm(derivedKey, sessionKeyData);

  const dataToStore = {
    peerId: peerId,
    encryptedSessionKey: ciphertext,
    iv: iv,
    tag: tag,
    salt: btoa(String.fromCharCode(...salt)),
  };

  const database = await openDb();
  const transaction = database.transaction(['sessionKeys'], 'readwrite');
  const store = transaction.objectStore('sessionKeys');

  await new Promise((resolve, reject) => {
    const request = store.put(dataToStore);
    request.onsuccess = () => resolve();
    request.onerror = (event) => reject(event.target.error);
  });
}

/**
 * Retrieves and decrypts a session key from IndexedDB.
 * @param {string} peerId
 * @param {string} password
 * @returns {Promise<JsonWebKey>}
 */
async function getDecryptedSessionKey(peerId, password) {
  const database = await openDb();
  const transaction = database.transaction(['sessionKeys'], 'readonly');
  const store = transaction.objectStore('sessionKeys');

  return new Promise((resolve, reject) => {
    const request = store.get(peerId);
    request.onsuccess = async (event) => {
      const data = event.target.result;
      if (!data) {
        // It's okay if no session key exists for a peer
        resolve(null);
        return;
      }

      try {
        const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
        const derivedKey = await deriveKeyFromPassword(password, salt);

        const decryptedDataBuffer = await decryptWithAesGcm(derivedKey, data.iv, data.encryptedSessionKey, data.tag);

        const decoder = new TextDecoder();
        const sessionKeyJwk = JSON.parse(decoder.decode(decryptedDataBuffer));
        resolve(sessionKeyJwk);
      } catch (err) {
        console.error(`Failed to decrypt session key for peer ${peerId}:`, err);
        resolve(null); // Return null on failure so we don't crash app
      }
    };
    request.onerror = (event) => reject(event.target.error);
  });
}

/**
 * Retrieves all encrypted session keys.
 * @returns {Promise<Array>}
 */
async function getAllEncryptedSessionKeys() {
  const database = await openDb();
  const transaction = database.transaction(['sessionKeys'], 'readonly');
  const store = transaction.objectStore('sessionKeys');

  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = (event) => {
      resolve(event.target.result);
    };
    request.onerror = (event) => reject(event.target.error);
  });
}


export {
  storeEncryptedPrivateKey,
  getDecryptedPrivateKey,
  storeEncryptedSessionKey,
  getDecryptedSessionKey,
  getAllEncryptedSessionKeys
};
