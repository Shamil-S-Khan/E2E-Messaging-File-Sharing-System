const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  conversationId: {
    type: String, // A string combining senderId and receiverId, sorted lexicographically
    required: true,
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
  ciphertext: {
    type: String, // Base64 encoded encrypted data
    required: true,
  },
  iv: {
    type: String, // Base64 encoded IV
    required: true,
  },
  authTag: {
    type: String, // Base64 encoded authentication tag
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  messageId: { // Unique ID for the message (nonce for replay protection)
    type: String,
    required: true,
    unique: true,
  },
  sequenceNumber: { // Sequence number for replay protection
    type: Number,
    default: 0,
  },
}, {
  timestamps: true,
});

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
