const mongoose = require('mongoose');

const securityLogSchema = new mongoose.Schema({
    eventType: {
        type: String,
        required: true,
        enum: [
            'auth_success',
            'auth_failure',
            'key_exchange_initiated',
            'key_exchange_completed',
            'key_exchange_failed',
            'message_sent',
            'message_decryption_failed',
            'replay_attack_detected',
            'invalid_signature',
            'mitm_attempt_detected',
            'file_upload',
            'file_download',
            'suspicious_activity'
        ]
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    ipAddress: {
        type: String,
        default: null
    },
    userAgent: {
        type: String,
        default: null
    },
    details: {
        type: mongoose.Schema.Types.Mixed, // Flexible object for event-specific data
        default: {}
    },
    severity: {
        type: String,
        enum: ['info', 'warning', 'error', 'critical'],
        default: 'info'
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    }
}, {
    timestamps: true
});

// Index for efficient querying
securityLogSchema.index({ eventType: 1, timestamp: -1 });
securityLogSchema.index({ userId: 1, timestamp: -1 });

const SecurityLog = mongoose.model('SecurityLog', securityLogSchema);

module.exports = SecurityLog;
