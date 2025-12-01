const SecurityLog = require('../models/SecurityLog');

/**
 * Centralized security logging service
 */
class SecurityLogger {
    /**
     * Log a security event
     * @param {string} eventType - Type of security event
     * @param {object} options - Event details
     */
    static async logEvent(eventType, options = {}) {
        try {
            const {
                userId = null,
                ipAddress = null,
                userAgent = null,
                details = {},
                severity = 'info',
                req = null
            } = options;

            // Extract IP and User-Agent from request if provided
            const logEntry = {
                eventType,
                userId,
                ipAddress: ipAddress || (req ? req.ip : null),
                userAgent: userAgent || (req ? req.get('user-agent') : null),
                details,
                severity,
                timestamp: new Date()
            };

            await SecurityLog.create(logEntry);

            // Also log to console for immediate visibility
            const logLevel = severity === 'critical' || severity === 'error' ? 'error' : 'log';
            console[logLevel](`[SECURITY ${severity.toUpperCase()}] ${eventType}:`, details);

            return true;
        } catch (error) {
            console.error('Failed to log security event:', error);
            return false;
        }
    }

    /**
     * Log authentication attempt
     */
    static async logAuthAttempt(success, username, req, reason = null) {
        return this.logEvent(
            success ? 'auth_success' : 'auth_failure',
            {
                req,
                details: { username, reason },
                severity: success ? 'info' : 'warning'
            }
        );
    }

    /**
     * Log key exchange event
     */
    static async logKeyExchange(status, userId, peerId, req, details = {}) {
        const eventMap = {
            'initiated': 'key_exchange_initiated',
            'completed': 'key_exchange_completed',
            'failed': 'key_exchange_failed'
        };

        return this.logEvent(
            eventMap[status] || 'key_exchange_initiated',
            {
                userId,
                req,
                details: { peerId, ...details },
                severity: status === 'failed' ? 'error' : 'info'
            }
        );
    }

    /**
     * Log replay attack detection
     */
    static async logReplayAttack(userId, details, req) {
        return this.logEvent(
            'replay_attack_detected',
            {
                userId,
                req,
                details,
                severity: 'critical'
            }
        );
    }

    /**
     * Log invalid signature
     */
    static async logInvalidSignature(userId, details, req) {
        return this.logEvent(
            'invalid_signature',
            {
                userId,
                req,
                details,
                severity: 'error'
            }
        );
    }

    /**
     * Log message decryption failure
     */
    static async logDecryptionFailure(userId, details, req) {
        return this.logEvent(
            'message_decryption_failed',
            {
                userId,
                req,
                details,
                severity: 'warning'
            }
        );
    }

    /**
     * Get recent security logs
     */
    static async getRecentLogs(limit = 100, filters = {}) {
        try {
            const query = {};

            if (filters.eventType) query.eventType = filters.eventType;
            if (filters.userId) query.userId = filters.userId;
            if (filters.severity) query.severity = filters.severity;
            if (filters.startDate) query.timestamp = { $gte: new Date(filters.startDate) };

            const logs = await SecurityLog.find(query)
                .sort({ timestamp: -1 })
                .limit(limit)
                .populate('userId', 'username')
                .lean();

            return logs;
        } catch (error) {
            console.error('Failed to retrieve security logs:', error);
            return [];
        }
    }

    /**
     * Get security statistics
     */
    static async getStatistics(timeRange = 24) {
        try {
            const since = new Date(Date.now() - timeRange * 60 * 60 * 1000);

            const stats = await SecurityLog.aggregate([
                { $match: { timestamp: { $gte: since } } },
                {
                    $group: {
                        _id: '$eventType',
                        count: { $sum: 1 },
                        criticalCount: {
                            $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
                        }
                    }
                }
            ]);

            return stats;
        } catch (error) {
            console.error('Failed to get security statistics:', error);
            return [];
        }
    }
}

module.exports = SecurityLogger;
