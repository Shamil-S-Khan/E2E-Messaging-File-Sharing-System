// client/src/services/fileService.js
import axios from 'axios';
import { encryptWithAesGcm, decryptWithAesGcm } from '../utils/cryptoUtils';

const API_URL = 'http://localhost:5000/api/files';
const CHUNK_SIZE = 256 * 1024; // 256 KB chunks

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

/**
 * Encrypts and uploads a file in chunks.
 * @param {File} file The file to upload.
 * @param {string} receiverId The recipient's user ID.
 * @param {CryptoKey} sessionKey The AES-256-GCM session key.
 * @param {function} onProgress Optional progress callback (0-100).
 * @returns {Promise<string>} The fileId of the uploaded file.
 */
export const uploadEncryptedFile = async (file, receiverId, sessionKey, onProgress) => {
  const fileId = `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

  // Initialize file upload on server
  await axios.post(`${API_URL}/init`, {
    receiverId,
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type || 'application/octet-stream',
    totalChunks,
    fileId,
  }, getAuthHeaders());

  // Read and encrypt file in chunks
  const arrayBuffer = await file.arrayBuffer();
  const fileData = new Uint8Array(arrayBuffer);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, fileData.length);
    const chunkData = fileData.slice(start, end);

    // Encrypt chunk with AES-256-GCM
    const { iv, ciphertext, tag } = await encryptWithAesGcm(sessionKey, chunkData);

    // Upload encrypted chunk
    await axios.post(`${API_URL}/chunk`, {
      fileId,
      chunkIndex: i,
      ciphertext,
      iv,
      authTag: tag,
    }, getAuthHeaders());

    if (onProgress) {
      onProgress(Math.round(((i + 1) / totalChunks) * 100));
    }
  }

  return fileId;
};

/**
 * Downloads and decrypts a file.
 * @param {string} fileId The file ID to download.
 * @param {CryptoKey} sessionKey The AES-256-GCM session key.
 * @param {function} onProgress Optional progress callback (0-100).
 * @returns {Promise<{blob: Blob, fileName: string, mimeType: string}>}
 */
export const downloadEncryptedFile = async (fileId, sessionKey, onProgress) => {
  // Get file metadata and encrypted chunks
  const response = await axios.get(`${API_URL}/${fileId}`, getAuthHeaders());
  const { fileName, mimeType, chunks, totalChunks } = response.data;

  // Decrypt chunks in order
  const decryptedChunks = [];

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const decryptedData = await decryptWithAesGcm(
      sessionKey,
      chunk.iv,
      chunk.ciphertext,
      chunk.authTag
    );
    decryptedChunks.push(decryptedData);

    if (onProgress) {
      onProgress(Math.round(((i + 1) / totalChunks) * 100));
    }
  }

  // Combine decrypted chunks
  const totalLength = decryptedChunks.reduce((acc, chunk) => acc + chunk.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of decryptedChunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  const blob = new Blob([combined], { type: mimeType });
  return { blob, fileName, mimeType };
};

/**
 * Lists files available to the current user.
 * @returns {Promise<Array>} Array of file metadata objects.
 */
export const listFiles = async () => {
  const response = await axios.get(API_URL, getAuthHeaders());
  return response.data;
};

const fileService = {
  uploadEncryptedFile,
  downloadEncryptedFile,
  listFiles,
  CHUNK_SIZE,
};

export default fileService;
