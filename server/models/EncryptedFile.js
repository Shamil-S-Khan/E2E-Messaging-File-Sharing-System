const mongoose = require('mongoose');

const encryptedFileSchema = new mongoose.Schema({
  fileId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  fileName: {
    type: String, // Original filename (can be encrypted or plaintext metadata)
    required: true,
  },
  fileSize: {
    type: Number, // Original file size in bytes
    required: true,
  },
  mimeType: {
    type: String,
    default: 'application/octet-stream',
  },
  totalChunks: {
    type: Number,
    required: true,
  },
  chunks: [{
    chunkIndex: { type: Number, required: true },
    ciphertext: { type: String, required: true }, // Base64 encrypted chunk
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
  }],
  status: {
    type: String,
    enum: ['uploading', 'complete', 'failed'],
    default: 'uploading',
  },
}, {
  timestamps: true,
});

const EncryptedFile = mongoose.model('EncryptedFile', encryptedFileSchema);

module.exports = EncryptedFile;
