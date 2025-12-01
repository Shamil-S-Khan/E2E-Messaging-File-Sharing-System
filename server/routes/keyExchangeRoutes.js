const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const User = require('../models/User');
const KeyExchangeSession = require('../models/KeyExchangeSession');
const logger = require('../utils/logger');

// Helper to get user's public RSA key (for signature verification)
async function getUserRsaPublicKey(userId) {
  const user = await User.findById(userId).select('publicKey');
  if (!user || !user.publicKey) {
    throw new Error(`User ${userId} not found or public key missing.`);
  }
  return user.publicKey; // This is the Base64 SPKI string of the RSA public key
}

// @desc    Initiate Key Exchange (Alice to Server)
// @route   POST /api/key-exchange/initiate
// @access  Private
router.post('/initiate', protect, async (req, res) => {
  const { responderId, initiatorEcdhPublicKey, initiatorSignature, initiatorTimestamp, nonceA } = req.body;
  const initiatorId = req.user._id;

  try {
    await logger.log('key_exchange', `Initiation by userId=${initiatorId} to responderId=${responderId}`);
    // 1. Verify initiator's RSA public key signature (This needs to be done client side as the server doesn't have the verifySignature crypto function)
    // The server just stores the signed ECDH public key and sends it to the responder.
    // Responder will verify Alice's signature with Alice's RSA public key (stored on server).

    // Create a session entry
    const session = await KeyExchangeSession.create({
      initiatorId,
      responderId,
      initiatorEcdhPublicKey,
      initiatorSignature,
      initiatorTimestamp,
      nonceA,
      status: 'initiated',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // Session expires in 10 minutes
    });

    await logger.log('key_exchange', `Initiation stored sessionId=${session._id} initiator=${initiatorId} responder=${responderId}`);
    res.status(201).json({ message: 'Key exchange initiated', sessionId: session._id });
  } catch (error) {
    await logger.log('key_exchange', `Initiation error initiator=${initiatorId} responder=${responderId} error=${error.message}`);
    res.status(500).json({ message: 'Server error during initiation', error: error.message });
  }
});

// @desc    Respond to Key Exchange (Bob to Server)
// @route   POST /api/key-exchange/respond
// @access  Private
router.post('/respond', protect, async (req, res) => {
  const { sessionId, responderEcdhPublicKey, responderSignature, responderTimestamp, nonceB } = req.body;
  const responderId = req.user._id;

  try {
    await logger.log('key_exchange', `Respond attempt by userId=${responderId} for sessionId=${sessionId}`);
    const session = await KeyExchangeSession.findById(sessionId);

    if (!session || session.responderId.toString() !== responderId.toString()) {
      return res.status(404).json({ message: 'Key exchange session not found or not authorized.' });
    }
    if (session.status !== 'initiated') {
        return res.status(400).json({ message: 'Key exchange session is not in initiated state.' });
    }

    // Update session with responder's data
    session.responderEcdhPublicKey = responderEcdhPublicKey;
    session.responderSignature = responderSignature;
    session.responderTimestamp = responderTimestamp;
    session.nonceB = nonceB;
    session.status = 'responded';
    await session.save();
    await logger.log('key_exchange', `Respond success sessionId=${session._id} responder=${responderId}`);

    res.json({ message: 'Key exchange response sent', sessionId: session._id });
  } catch (error) {
    await logger.log('key_exchange', `Respond error sessionId=${sessionId} responder=${responderId} error=${error.message}`);
    res.status(500).json({ message: 'Server error during response', error: error.message });
  }
});

// @desc    Confirm Key Exchange (Alice to Server)
// @route   POST /api/key-exchange/confirm
// @access  Private
router.post('/confirm', protect, async (req, res) => {
  const { sessionId, confirmationMac } = req.body;
  const initiatorId = req.user._id;

  try {
    await logger.log('key_exchange', `Confirm attempt by userId=${initiatorId} sessionId=${sessionId}`);
    const session = await KeyExchangeSession.findById(sessionId);

    if (!session || session.initiatorId.toString() !== initiatorId.toString()) {
      return res.status(404).json({ message: 'Key exchange session not found or not authorized.' });
    }
    if (session.status !== 'responded') {
        return res.status(400).json({ message: 'Key exchange session is not in responded state.' });
    }

    // Store Alice's confirmation MAC
    session.confirmationMac = confirmationMac;
    session.status = 'confirmed';
    await session.save();
    await logger.log('key_exchange', `Confirm success sessionId=${session._id} initiator=${initiatorId}`);

    res.json({ message: 'Key exchange confirmed', sessionId: session._id });
  } catch (error) {
    await logger.log('key_exchange', `Confirm error sessionId=${sessionId} initiator=${initiatorId} error=${error.message}`);
    res.status(500).json({ message: 'Server error during confirmation', error: error.message });
  }
});

// @desc    Acknowledge Key Exchange (Bob to Server)
// @route   POST /api/key-exchange/ack
// @access  Private
router.post('/ack', protect, async (req, res) => {
  const { sessionId, acknowledgementMac } = req.body;
  const responderId = req.user._id;

  try {
    await logger.log('key_exchange', `Ack attempt by userId=${responderId} sessionId=${sessionId}`);
    const session = await KeyExchangeSession.findById(sessionId);

    if (!session || session.responderId.toString() !== responderId.toString()) {
      return res.status(404).json({ message: 'Key exchange session not found or not authorized.' });
    }
    if (session.status !== 'confirmed') {
        return res.status(400).json({ message: 'Key exchange session is not in confirmed state.' });
    }

    // Store Bob's acknowledgement MAC
    session.acknowledgementMac = acknowledgementMac;
    session.status = 'completed'; // Key exchange is now completed
    await session.save();
    await logger.log('key_exchange', `Ack success sessionId=${session._id} responder=${responderId}`);

    res.json({ message: 'Key exchange acknowledged and completed', sessionId: session._id });
  } catch (error) {
    await logger.log('key_exchange', `Ack error sessionId=${sessionId} responder=${responderId} error=${error.message}`);
    res.status(500).json({ message: 'Server error during acknowledgement', error: error.message });
  }
});

// @desc    Get Key Exchange Session details for a specific user
// @route   GET /api/key-exchange/session/:sessionId
// @access  Private
router.get('/session/:sessionId', protect, async (req, res) => {
  const { sessionId } = req.params;
  const userId = req.user._id;

  try {
    const session = await KeyExchangeSession.findById(sessionId);

    if (!session || (session.initiatorId.toString() !== userId.toString() && session.responderId.toString() !== userId.toString())) {
      return res.status(404).json({ message: 'Key exchange session not found or not authorized.' });
    }
    
    // Fetch initiator and responder usernames for client display
    const initiator = await User.findById(session.initiatorId).select('username');
    const responder = await User.findById(session.responderId).select('username');

    res.json({
        ...session.toObject(),
        initiatorUsername: initiator ? initiator.username : 'Unknown',
        responderUsername: responder ? responder.username : 'Unknown',
    });
  } catch (error) {
    console.error('Failed to get key exchange session:', error);
    res.status(500).json({ message: 'Server error fetching session', error: error.message });
  }
});


// @desc    Get Key Exchange Session details for a specific user
// @route   GET /api/key-exchange/session/:sessionId
// @access  Private
router.get('/session/:sessionId', protect, async (req, res) => {
  const { sessionId } = req.params;
  const userId = req.user._id;

  try {
    const session = await KeyExchangeSession.findById(sessionId);

    if (!session || (session.initiatorId.toString() !== userId.toString() && session.responderId.toString() !== userId.toString())) {
      return res.status(404).json({ message: 'Key exchange session not found or not authorized.' });
    }
    
    // Fetch initiator and responder usernames for client display
    const initiator = await User.findById(session.initiatorId).select('username');
    const responder = await User.findById(session.responderId).select('username');

    res.json({
        ...session.toObject(),
        initiatorUsername: initiator ? initiator.username : 'Unknown',
        responderUsername: responder ? responder.username : 'Unknown',
    });
  } catch (error) {
    console.error('Failed to get key exchange session:', error);
    res.status(500).json({ message: 'Server error fetching session', error: error.message });
  }
});

// @desc    Get all key exchange sessions relevant to the current user
// @route   GET /api/key-exchange/my-sessions
// @access  Private
router.get('/my-sessions', protect, async (req, res) => {
    const userId = req.user._id;
    try {
        const sessions = await KeyExchangeSession.find({
            $or: [
                { initiatorId: userId },
                { responderId: userId }
            ]
        }).populate('initiatorId', 'username publicKey').populate('responderId', 'username publicKey');

        // Filter out expired sessions if desired, or handle on client
        res.json(sessions);
    } catch (error) {
        console.error('Failed to get user-specific key exchange sessions:', error);
        res.status(500).json({ message: 'Server error fetching user sessions', error: error.message });
    }
});


module.exports = router;