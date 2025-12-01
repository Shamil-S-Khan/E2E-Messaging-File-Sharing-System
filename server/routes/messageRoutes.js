const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const Message = require('../models/Message');
const User = require('../models/User');
const logger = require('../utils/logger');
const SecurityLogger = require('../services/securityLogger');
const ReplayDetector = require('../services/replayDetector');

// Helper to generate a consistent conversation ID
const getConversationId = (userId1, userId2) => {
  return [userId1, userId2].sort().join('-');
};

// @desc    Send a new encrypted message
// @route   POST /api/messages
// @access  Private
router.post('/', protect, async (req, res) => {
  const { receiverId, ciphertext, iv, authTag, messageId, timestamp, sequenceNumber } = req.body;
  const senderId = req.user._id;

  if (!receiverId || !ciphertext || !iv || !authTag || !messageId) {
    return res.status(400).json({ message: 'Missing required message fields.' });
  }

  if (!sequenceNumber || sequenceNumber <= 0) {
    return res.status(400).json({ message: 'Invalid or missing sequence number.' });
  }

  try {
    // Basic validation: ensure receiver exists
    const receiverExists = await User.findById(receiverId);
    if (!receiverExists) {
      return res.status(404).json({ message: 'Receiver not found.' });
    }

    const conversationId = getConversationId(senderId.toString(), receiverId.toString());

    // --- REPLAY ATTACK PROTECTION ---
    const validation = ReplayDetector.validateMessage(
      conversationId,
      sequenceNumber,
      messageId,
      timestamp || new Date()
    );

    if (!validation.valid) {
      // Log replay attack attempt
      await SecurityLogger.logReplayAttack(
        senderId,
        {
          reason: validation.reason,
          details: validation.details,
          receiverId,
          messageId,
          sequenceNumber
        },
        req
      );

      return res.status(400).json({
        message: 'Replay attack detected.',
        reason: validation.reason
      });
    }

    // Record message as valid
    ReplayDetector.recordMessage(conversationId, sequenceNumber, messageId);

    const message = await Message.create({
      senderId,
      receiverId,
      conversationId,
      ciphertext,
      iv,
      authTag,
      messageId,
      sequenceNumber,
      timestamp: timestamp || new Date(),
    });

    // Log successful message send
    await SecurityLogger.logEvent('message_sent', {
      userId: senderId,
      req,
      details: {
        receiverId,
        messageId,
        sequenceNumber,
        conversationId
      },
      severity: 'info'
    });

    res.status(201).json(message);
  } catch (error) {
    console.error('Error sending message:', error);
    await logger.log('error', `Message send failed: ${error.message}`);
    res.status(500).json({ message: 'Server error sending message', error: error.message });
  }
});

// @desc    Get encrypted messages for a specific conversation
// @route   GET /api/messages/:peerId
// @access  Private
router.get('/:peerId', protect, async (req, res) => {
  const currentUserId = req.user._id;
  const { peerId } = req.params;
  const { since } = req.query; // Get 'since' timestamp from query

  try {
    await logger.log('metadata_access', `Message metadata accessed userId=${currentUserId} peerId=${peerId} since=${since || 'all'}`);

    // Validate peerId exists
    const peerExists = await User.findById(peerId);
    if (!peerExists) {
      return res.status(404).json({ message: 'Peer not found.' });
    }

    const conversationId = getConversationId(currentUserId.toString(), peerId.toString());

    let query = { conversationId };
    if (since) {
      const sinceDate = new Date(since);
      query.timestamp = { $gt: sinceDate };
    }

    const messages = await Message.find(query)
      .sort('timestamp')
      .populate('senderId', 'username')
      .populate('receiverId', 'username');

    await logger.log('metadata_access', `Retrieved ${messages.length} messages userId=${currentUserId} peerId=${peerId}`);
    res.json(messages);
  } catch (error) {
    await logger.log('metadata_access', `Fetch error userId=${currentUserId} peerId=${peerId} error=${error.message}`);
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error fetching messages', error: error.message });
  }
});

// @desc    Report a client-side security event
// @route   POST /api/messages/security-event
// @access  Private
router.post('/security-event', protect, async (req, res) => {
  const { eventType, details } = req.body;
  const userId = req.user._id;

  const validEventTypes = [
    'decryption_failed',
    'invalid_signature',
    'key_exchange_failed',
    'invalid_mac',
    'tampered_message'
  ];

  if (!eventType || !validEventTypes.includes(eventType)) {
    return res.status(400).json({ message: 'Invalid event type' });
  }

  await logger.log('client_security_event', `${eventType} reported by userId=${userId} details=${JSON.stringify(details || {})}`);

  res.json({ message: 'Security event logged' });
});

module.exports = router;
