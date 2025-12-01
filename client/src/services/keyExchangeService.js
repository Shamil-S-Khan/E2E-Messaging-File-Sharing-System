import axios from 'axios';
import {
  generateECDHKeyPair,
  exportKeyToJwk,
  importKeyFromJwk,
  signData,
  verifySignature,
  importPublicKeyFromSpkiBase64,
  deriveSharedSecret,
  deriveSessionKey as cryptoDeriveSessionKey,
  createMac,
  verifyMac,
} from '../utils/cryptoUtils';
import { getDecryptedPrivateKey } from './indexedDbService'; // To get our RSA private key

const API_URL = 'http://localhost:5000/api/key-exchange';

// Helper to get authenticated config
const getAuthHeaders = () => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user || !user.token) {
    throw new Error('User not authenticated.');
  }
  return {
    headers: {
      Authorization: `Bearer ${user.token}`,
      'Content-Type': 'application/json',
    },
  };
};

// Helper to convert string to Uint8Array
const strToUint8 = (str) => new TextEncoder().encode(str);
const uint8ToStr = (uint8) => new TextDecoder().decode(uint8);

/**
 * Initiates the key exchange protocol (Alice's side).
 * @param {string} responderId The ID of the user Alice wants to chat with.
 * @param {CryptoKeyPair} rsaKeyPair Alice's RSA key pair (private for signing).
 * @returns {Promise<{sessionId: string, ecdhKeyPair: CryptoKeyPair}>}
 */
const initiateKeyExchange = async (responderId, rsaKeyPair) => {
  const authHeaders = getAuthHeaders();
  const userId = JSON.parse(localStorage.getItem('user'))._id;

  // 1. Generate Alice's ECDH key pair
  const ecdhKeyPair = await generateECDHKeyPair();
  const initiatorEcdhPublicKeyJwk = await exportKeyToJwk(ecdhKeyPair.publicKey);
  const initiatorEcdhPublicKeyJwkStr = JSON.stringify(initiatorEcdhPublicKeyJwk);

  // 2. Prepare data to sign: ECDH public key + timestamp
  const initiatorTimestamp = Date.now().toString();
  const dataToSign = strToUint8(initiatorEcdhPublicKeyJwkStr + initiatorTimestamp);

  // 3. Alice signs the data with her RSA private key
  const initiatorSignature = await signData(rsaKeyPair.privateKey, dataToSign);

  // 4. Generate NonceA for session key derivation
  const nonceA = window.crypto.getRandomValues(new Uint8Array(16)); // 16 bytes for NonceA

  const payload = {
    responderId,
    initiatorEcdhPublicKey: initiatorEcdhPublicKeyJwkStr,
    initiatorSignature,
    initiatorTimestamp,
    nonceA: btoa(String.fromCharCode(...nonceA)), // Base64 encode nonce
  };

  const response = await axios.post(`${API_URL}/initiate`, payload, authHeaders);

  return { sessionId: response.data.sessionId, ecdhKeyPair, nonceA };
};

/**
 * Responds to a key exchange initiation (Bob's side).
 * @param {object} sessionData Initial session data from Alice's initiation (from server)
 * @param {CryptoKeyPair} rsaKeyPair Bob's RSA key pair (private for signing).
 * @param {string} myUserId Bob's user ID.
 * @param {string} aliceRsaPublicKeySpkiBase64 Alice's RSA public key (from DB)
 * @returns {Promise<{sessionId: string, ecdhKeyPair: CryptoKeyPair, sessionKey: CryptoKey, nonceB: Uint8Array}>}
 */
const respondToKeyExchange = async (sessionData, rsaKeyPair, myUserId, aliceRsaPublicKeySpkiBase64) => {
  const authHeaders = getAuthHeaders();

  // 1. Verify Alice's signature
  const aliceRsaPublicKey = await importPublicKeyFromSpkiBase64(aliceRsaPublicKeySpkiBase64);
  const initiatorEcdhPublicKeyJwkStr = sessionData.initiatorEcdhPublicKey;
  const initiatorTimestamp = sessionData.initiatorTimestamp;
  const initiatorSignature = sessionData.initiatorSignature;
  const nonceA = Uint8Array.from(atob(sessionData.nonceA), c => c.charCodeAt(0));

  const dataSignedByAlice = strToUint8(initiatorEcdhPublicKeyJwkStr + initiatorTimestamp);
  const isAliceSignatureValid = await verifySignature(aliceRsaPublicKey, initiatorSignature, dataSignedByAlice);

  if (!isAliceSignatureValid) {
    throw new Error("Alice's signature is invalid. MITM attack possible.");
  }

  // 2. Generate Bob's ECDH key pair
  const ecdhKeyPair = await generateECDHKeyPair();
  const responderEcdhPublicKeyJwk = await exportKeyToJwk(ecdhKeyPair.publicKey);
  const responderEcdhPublicKeyJwkStr = JSON.stringify(responderEcdhPublicKeyJwk);

  // 3. Prepare data to sign: Bob's ECDH public key + timestamp
  const responderTimestamp = Date.now().toString();
  const dataToSignByBob = strToUint8(responderEcdhPublicKeyJwkStr + responderTimestamp);

  // 4. Bob signs the data with his RSA private key
  const responderSignature = await signData(rsaKeyPair.privateKey, dataToSignByBob);

  // 5. Generate NonceB for session key derivation
  const nonceB = window.crypto.getRandomValues(new Uint8Array(16)); // 16 bytes for NonceB

  // 6. Derive shared secret
  // Import with empty usages [] because this public key is used as a parameter for deriveKey, not the key being derived from.
  const aliceEcdhPublicKey = await importKeyFromJwk(JSON.parse(initiatorEcdhPublicKeyJwkStr), 'ECDH', []);
  const sharedSecret = await deriveSharedSecret(ecdhKeyPair.privateKey, aliceEcdhPublicKey);

  // 7. Derive session key
  const sessionKey = await cryptoDeriveSessionKey(sharedSecret, nonceA, nonceB);

  const payload = {
    sessionId: sessionData._id,
    responderEcdhPublicKey: responderEcdhPublicKeyJwkStr,
    responderSignature,
    responderTimestamp,
    nonceB: btoa(String.fromCharCode(...nonceB)), // Base64 encode nonce
  };

  await axios.post(`${API_URL}/respond`, payload, authHeaders);

  return { sessionId: sessionData._id, ecdhKeyPair, sessionKey, nonceB };
};


/**
 * Alice sends key confirmation to Bob.
 * @param {string} sessionId
 * @param {CryptoKey} sessionKey
 * @param {Uint8Array} nonceA Alice's nonce.
 * @returns {Promise<void>}
 */
const confirmKeyExchange = async (sessionId, sessionKey, nonceA) => {
  const authHeaders = getAuthHeaders();

  // Create MAC for "CONFIRMED"
  const mac = await createMac(sessionKey, "CONFIRMED");

  const payload = {
    sessionId,
    confirmationMac: mac,
    nonceA: btoa(String.fromCharCode(...nonceA)), // Include NonceA again for confirmation
  };

  await axios.post(`${API_URL}/confirm`, payload, authHeaders);
};

/**
 * Bob sends key acknowledgement to Alice.
 * @param {object} sessionData
 * @param {CryptoKey} sessionKey
 * @param {Uint8Array} nonceB Bob's nonce.
 * @param {string} aliceRsaPublicKeySpkiBase64 Alice's RSA public key (from DB)
 * @returns {Promise<void>}
 */
const acknowledgeKeyExchange = async (sessionData, sessionKey, nonceB, aliceRsaPublicKeySpkiBase64) => {
  const authHeaders = getAuthHeaders();

  // Verify Alice's confirmation MAC
  const isMacValid = await verifyMac(sessionKey, sessionData.confirmationMac, "CONFIRMED");
  if (!isMacValid) {
    throw new Error("Alice's confirmation MAC is invalid. Key exchange failed.");
  }

  // Create MAC for "ACK"
  const ackMac = await createMac(sessionKey, "ACK");

  const payload = {
    sessionId: sessionData._id,
    acknowledgementMac: ackMac,
    nonceB: btoa(String.fromCharCode(...nonceB)), // Include NonceB again for acknowledgement
  };

  await axios.post(`${API_URL}/ack`, payload, authHeaders);
};

/**
 * Fetches a specific key exchange session from the server.
 * @param {string} sessionId
 * @returns {Promise<object>}
 */
const getKeyExchangeSession = async (sessionId) => {
  const authHeaders = getAuthHeaders();
  const response = await axios.get(`${API_URL}/session/${sessionId}`, authHeaders);
  return response.data;
}

/**
 * Fetches all key exchange sessions relevant to the current user.
 * @returns {Promise<object[]>}
 */
const getMySessions = async () => {
  const authHeaders = getAuthHeaders();
  const response = await axios.get(`${API_URL}/my-sessions`, authHeaders);
  return response.data;
}

const keyExchangeService = {
  initiateKeyExchange,
  respondToKeyExchange,
  confirmKeyExchange,
  acknowledgeKeyExchange,
  getKeyExchangeSession,
  getMySessions,
};

export default keyExchangeService;
