const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { protect } = require('../middleware/authMiddleware');
const logger = require('../utils/logger');
const SecurityLogger = require('../services/securityLogger');

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    await logger.log('auth', `Register attempt for username=${username}`);
    const userExists = await User.findOne({ username });

    if (userExists) {
      await SecurityLogger.logAuthAttempt(false, username, req, 'User already exists');
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = await User.create({
      username,
      password,
    });

    if (user) {
      await SecurityLogger.logAuthAttempt(true, username, req);
      await logger.log('auth', `Register success username=${username} userId=${user._id}`);
      res.status(201).json({
        _id: user._id,
        username: user.username,
        token: generateToken(user._id),
      });
    } else {
      await SecurityLogger.logAuthAttempt(false, username, req, 'Invalid user data');
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    await SecurityLogger.logAuthAttempt(false, username, req, error.message);
    await logger.log('auth', `Register error username=${username} error=${error.message}`);
    res.status(500).json({ message: error.message });
  }
});

// @desc    Authenticate a user
// @route   POST /api/auth/login
// @access  Public
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    await logger.log('auth', `Login attempt username=${username}`);
    const user = await User.findOne({ username });

    if (user && (await user.matchPassword(password))) {
      await SecurityLogger.logAuthAttempt(true, username, req);
      await logger.log('auth', `Login success username=${username} userId=${user._id}`);
      res.json({
        _id: user._id,
        username: user.username,
        token: generateToken(user._id),
      });
    } else {
      await SecurityLogger.logAuthAttempt(false, username, req, 'Invalid credentials');
      await logger.log('auth', `Login failed username=${username}`);
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    await SecurityLogger.logAuthAttempt(false, username, req, error.message);
    await logger.log('auth', `Login error username=${username} error=${error.message}`);
    res.status(500).json({ message: error.message });
  }
});

// @desc    Get user profile (Protected)
// @route   GET /api/auth/profile
// @access  Private
router.get('/profile', protect, async (req, res) => {
  await logger.log('auth', `Profile accessed userId=${req.user._id}`);
  res.json({
    _id: req.user._id,
    username: req.user.username,
  });
});

// @desc    Upload user's public key
// @route   PUT /api/auth/publicKey
// @access  Private
router.put('/publicKey', protect, async (req, res) => {
  const { publicKey } = req.body;

  if (!publicKey) {
    return res.status(400).json({ message: 'Public key is required' });
  }

  try {
    const user = await User.findById(req.user._id);

    if (user) {
      user.publicKey = publicKey;
      await user.save();
      await logger.log('auth', `Public key uploaded userId=${req.user._id}`);
      res.json({ message: 'Public key updated successfully' });
    } else {
      await logger.log('auth', `Public key upload failed - user not found userId=${req.user._id}`);
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    await logger.log('auth', `Public key upload error userId=${req.user._id} error=${error.message}`);
    res.status(500).json({ message: error.message });
  }
});

// @desc    Get all users (excluding self and password)
// @route   GET /api/auth/users
// @access  Private
router.get('/users', protect, async (req, res) => {
  try {
    await logger.log('auth', `Users list requested by userId=${req.user._id}`);
    const users = await User.find({ _id: { $ne: req.user._id } }).select('_id username publicKey');
    res.json(users);
  } catch (error) {
    await logger.log('auth', `Users list error userId=${req.user._id} error=${error.message}`);
    res.status(500).json({ message: 'Server error fetching users', error: error.message });
  }
});

module.exports = router;