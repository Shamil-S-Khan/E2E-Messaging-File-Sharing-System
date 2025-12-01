/**
 * Replay Attack Detection Service
 * Tracks message sequence numbers and timestamps to prevent replay attacks
 */

// In-memory store for sequence tracking (in production, use Redis or database)
const sequenceStore = new Map();
const SEQUENCE_WINDOW = 100; // Allow messages within this sequence window
const TIME_WINDOW = 5 * 60 * 1000; // 5 minutes in milliseconds

class ReplayDetector {
    /**
     * Initialize sequence tracking for a conversation
     */
    static initConversation(conversationId) {
        if (!sequenceStore.has(conversationId)) {
            sequenceStore.set(conversationId, {
                lastSequence: 0,
                receivedSequences: new Set(),
                receivedMessageIds: new Set(),
                lastCleanup: Date.now()
            });
        }
    }

    /**
     * Validate a message against replay attacks
     * @param {string} conversationId - Conversation identifier
     * @param {number} sequenceNumber - Message sequence number
     * @param {string} messageId - Unique message identifier (nonce)
     * @param {Date} timestamp - Message timestamp
     * @returns {object} - { valid: boolean, reason: string }
     */
    static validateMessage(conversationId, sequenceNumber, messageId, timestamp) {
        this.initConversation(conversationId);
        const conv = sequenceStore.get(conversationId);

        // Check 1: Message ID uniqueness (nonce check)
        if (conv.receivedMessageIds.has(messageId)) {
            return {
                valid: false,
                reason: 'REPLAY_ATTACK_DUPLICATE_MESSAGE_ID',
                details: { messageId, conversationId }
            };
        }

        // Check 2: Timestamp freshness
        const messageTime = new Date(timestamp).getTime();
        const now = Date.now();

        if (messageTime > now + 60000) { // Message from future (1 min tolerance)
            return {
                valid: false,
                reason: 'REPLAY_ATTACK_FUTURE_TIMESTAMP',
                details: { timestamp, messageTime, now }
            };
        }

        if (now - messageTime > TIME_WINDOW) { // Message too old
            return {
                valid: false,
                reason: 'REPLAY_ATTACK_EXPIRED_TIMESTAMP',
                details: { timestamp, messageTime, now, ageMs: now - messageTime }
            };
        }

        // Check 3: Sequence number validation
        if (sequenceNumber <= 0) {
            return {
                valid: false,
                reason: 'INVALID_SEQUENCE_NUMBER',
                details: { sequenceNumber }
            };
        }

        // Check if sequence number was already received
        if (conv.receivedSequences.has(sequenceNumber)) {
            return {
                valid: false,
                reason: 'REPLAY_ATTACK_DUPLICATE_SEQUENCE',
                details: { sequenceNumber, conversationId }
            };
        }

        // Check if sequence number is within acceptable window
        if (sequenceNumber < conv.lastSequence - SEQUENCE_WINDOW) {
            return {
                valid: false,
                reason: 'REPLAY_ATTACK_OLD_SEQUENCE',
                details: {
                    sequenceNumber,
                    lastSequence: conv.lastSequence,
                    window: SEQUENCE_WINDOW
                }
            };
        }

        // All checks passed - message is valid
        return { valid: true };
    }

    /**
     * Record a validated message
     */
    static recordMessage(conversationId, sequenceNumber, messageId) {
        this.initConversation(conversationId);
        const conv = sequenceStore.get(conversationId);

        // Update last sequence if this is newer
        if (sequenceNumber > conv.lastSequence) {
            conv.lastSequence = sequenceNumber;
        }

        // Record sequence and message ID
        conv.receivedSequences.add(sequenceNumber);
        conv.receivedMessageIds.add(messageId);

        // Cleanup old data periodically (every 5 minutes)
        if (Date.now() - conv.lastCleanup > 5 * 60 * 1000) {
            this.cleanup(conversationId);
            conv.lastCleanup = Date.now();
        }
    }

    /**
     * Cleanup old sequence numbers and message IDs
     */
    static cleanup(conversationId) {
        const conv = sequenceStore.get(conversationId);
        if (!conv) return;

        // Keep only recent sequences (within window)
        const minSequence = conv.lastSequence - SEQUENCE_WINDOW;
        conv.receivedSequences = new Set(
            Array.from(conv.receivedSequences).filter(seq => seq > minSequence)
        );

        // Limit message ID cache size (keep last 1000)
        if (conv.receivedMessageIds.size > 1000) {
            const idsArray = Array.from(conv.receivedMessageIds);
            conv.receivedMessageIds = new Set(idsArray.slice(-1000));
        }
    }

    /**
     * Get next sequence number for a conversation
     */
    static getNextSequence(conversationId) {
        this.initConversation(conversationId);
        const conv = sequenceStore.get(conversationId);
        return conv.lastSequence + 1;
    }

    /**
     * Reset conversation tracking (for testing)
     */
    static resetConversation(conversationId) {
        sequenceStore.delete(conversationId);
    }

    /**
     * Get statistics for monitoring
     */
    static getStats() {
        const stats = {};
        for (const [convId, data] of sequenceStore.entries()) {
            stats[convId] = {
                lastSequence: data.lastSequence,
                trackedSequences: data.receivedSequences.size,
                trackedMessageIds: data.receivedMessageIds.size
            };
        }
        return stats;
    }
}

module.exports = ReplayDetector;
