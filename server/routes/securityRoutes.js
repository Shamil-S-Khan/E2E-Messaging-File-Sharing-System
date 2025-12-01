const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const SecurityLogger = require('../services/securityLogger');
const SecurityLog = require('../models/SecurityLog');

// @desc    Get security logs (admin/monitoring)
// @route   GET /api/security/logs
// @access  Private
router.get('/logs', protect, async (req, res) => {
    try {
        const {
            limit = 100,
            eventType,
            severity,
            startDate,
            userId
        } = req.query;

        const filters = {};
        if (eventType) filters.eventType = eventType;
        if (severity) filters.severity = severity;
        if (userId) filters.userId = userId;
        if (startDate) filters.startDate = startDate;

        const logs = await SecurityLogger.getRecentLogs(parseInt(limit), filters);

        res.json({
            count: logs.length,
            logs
        });
    } catch (error) {
        console.error('Error fetching security logs:', error);
        res.status(500).json({ message: 'Failed to fetch security logs', error: error.message });
    }
});

// @desc    Get security statistics
// @route   GET /api/security/stats
// @access  Private
router.get('/stats', protect, async (req, res) => {
    try {
        const { timeRange = 24 } = req.query; // hours
        const stats = await SecurityLogger.getStatistics(parseInt(timeRange));

        res.json({
            timeRange: `${timeRange} hours`,
            statistics: stats
        });
    } catch (error) {
        console.error('Error fetching security statistics:', error);
        res.status(500).json({ message: 'Failed to fetch statistics', error: error.message });
    }
});

// @desc    Get replay attack detection stats
// @route   GET /api/security/replay-stats
// @access  Private
router.get('/replay-stats', protect, async (req, res) => {
    try {
        const ReplayDetector = require('../services/replayDetector');
        const stats = ReplayDetector.getStats();

        res.json({
            conversations: stats,
            totalConversations: Object.keys(stats).length
        });
    } catch (error) {
        console.error('Error fetching replay stats:', error);
        res.status(500).json({ message: 'Failed to fetch replay stats', error: error.message });
    }
});

// @desc    Get recent security events by type
// @route   GET /api/security/events/:eventType
// @access  Private
router.get('/events/:eventType', protect, async (req, res) => {
    try {
        const { eventType } = req.params;
        const { limit = 50 } = req.query;

        const events = await SecurityLog.find({ eventType })
            .sort({ timestamp: -1 })
            .limit(parseInt(limit))
            .populate('userId', 'username')
            .lean();

        res.json({
            eventType,
            count: events.length,
            events
        });
    } catch (error) {
        console.error('Error fetching security events:', error);
        res.status(500).json({ message: 'Failed to fetch events', error: error.message });
    }
});

module.exports = router;
