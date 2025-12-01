const mongoose = require('mongoose');

const KeyExchangeSessionSchema = new mongoose.Schema({
  initiatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  responderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  status: {
    type: String,
    enum: ['initiated', 'responded', 'confirmed', 'completed', 'failed'],
    default: 'initiated',
  },
  // Alice's ECDH public key
  initiatorEcdhPublicKey: {
    type: String, // JWK string
    required: true,
  },
  // Alice's signature over her ECDH public key and timestamp
  initiatorSignature: {
    type: String,
    required: true,
  },
  initiatorTimestamp: {
    type: String,
    required: true,
  },
  // Alice's Nonce for Session Key Derivation
  nonceA: {
    type: String, // Base64 encoded Uint8Array
    default: null,
  },

  // Bob's ECDH public key
  responderEcdhPublicKey: {
    type: String, // JWK string
    default: null,
  },
  // Bob's signature over his ECDH public key and timestamp
  responderSignature: {
    type: String,
    default: null,
  },
  responderTimestamp: {
    type: String,
    default: null,
  },
  // Bob's Nonce for Session Key Derivation
  nonceB: {
    type: String, // Base64 encoded Uint8Array
    default: null,
  },

  // Key Confirmation (MACs)
  confirmationMac: {
    type: String, // Base64 encoded MAC from Alice
    default: null,
  },
  acknowledgementMac: {
    type: String, // Base64 encoded MAC from Bob
    default: null,
  },
  
  // Storing the derived session key ID temporarily or reference to a more secure storage
  // For this step, we'll confirm its derivation on both sides.
  // The actual session key will be managed client-side.

  createdAt: {
    type: Date,
    default: Date.now,
  },
  expiresAt: { // Sessions should expire after a certain time to prevent stale data
    type: Date,
    required: true,
  }
});

const KeyExchangeSession = mongoose.model('KeyExchangeSession', KeyExchangeSessionSchema);

module.exports = KeyExchangeSession;
