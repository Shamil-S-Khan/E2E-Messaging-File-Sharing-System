const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const EncryptedFile = require('../models/EncryptedFile');
const User = require('../models/User');
const logger = require('../utils/logger');

// @desc    Initialize a file upload (create file record)
// @route   POST /api/files/init
// @access  Private
router.post('/init', protect, async (req, res) => {
  const { receiverId, fileName, fileSize, mimeType, totalChunks, fileId } = req.body;
  const senderId = req.user._id;

  if (!receiverId || !fileName || !fileSize || !totalChunks || !fileId) {
    return res.status(400).json({ message: 'Missing required fields for file init.' });
  }

  try {
    await logger.log('file', `File init sender=${senderId} receiver=${receiverId} fileId=${fileId} fileName=${fileName} size=${fileSize} chunks=${totalChunks}`);

    const receiverExists = await User.findById(receiverId);
    if (!receiverExists) {
      return res.status(404).json({ message: 'Receiver not found.' });
    }

    const file = await EncryptedFile.create({
      fileId,
      senderId,
      receiverId,
      fileName,
      fileSize,
      mimeType: mimeType || 'application/octet-stream',
      totalChunks,
      chunks: [],
      status: 'uploading',
    });

    res.status(201).json({ message: 'File upload initialized', fileId: file.fileId });
  } catch (error) {
    await logger.log('file', `File init error sender=${senderId} error=${error.message}`);
    res.status(500).json({ message: 'Server error initializing file upload', error: error.message });
  }
});

// @desc    Upload an encrypted chunk
// @route   POST /api/files/chunk
// @access  Private
router.post('/chunk', protect, async (req, res) => {
  const { fileId, chunkIndex, ciphertext, iv, authTag } = req.body;
  const userId = req.user._id;

  if (!fileId || typeof chunkIndex !== 'number' || !ciphertext || !iv || !authTag) {
    return res.status(400).json({ message: 'Missing required fields for chunk upload.' });
  }

  try {
    const file = await EncryptedFile.findOne({ fileId });
    if (!file) {
      return res.status(404).json({ message: 'File not found.' });
    }
    if (file.senderId.toString() !== userId.toString()) {
      return res.status(403).json({ message: 'Not authorized to upload chunks to this file.' });
    }

    // Check if chunk already exists
    const existingChunk = file.chunks.find(c => c.chunkIndex === chunkIndex);
    if (existingChunk) {
      return res.status(400).json({ message: 'Chunk already uploaded.' });
    }

    file.chunks.push({ chunkIndex, ciphertext, iv, authTag });

    // Mark complete if all chunks received
    if (file.chunks.length === file.totalChunks) {
      file.status = 'complete';
      await logger.log('file', `File upload complete fileId=${fileId} sender=${userId}`);
    }

    await file.save();
    res.json({ message: 'Chunk uploaded', chunksReceived: file.chunks.length, totalChunks: file.totalChunks });
  } catch (error) {
    await logger.log('file', `Chunk upload error fileId=${fileId} error=${error.message}`);
    res.status(500).json({ message: 'Server error uploading chunk', error: error.message });
  }
});

// @desc    List files sent to or by the current user
// @route   GET /api/files
// @access  Private
router.get('/', protect, async (req, res) => {
  const userId = req.user._id;

  try {
    const files = await EncryptedFile.find({
      $or: [{ senderId: userId }, { receiverId: userId }],
      status: 'complete',
    })
      .select('fileId fileName fileSize mimeType senderId receiverId createdAt')
      .populate('senderId', 'username')
      .populate('receiverId', 'username')
      .sort('-createdAt');

    res.json(files);
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching files', error: error.message });
  }
});

// @desc    Download encrypted file (all chunks)
// @route   GET /api/files/:fileId
// @access  Private
router.get('/:fileId', protect, async (req, res) => {
  const { fileId } = req.params;
  const userId = req.user._id;

  try {
    const file = await EncryptedFile.findOne({ fileId });
    if (!file) {
      return res.status(404).json({ message: 'File not found.' });
    }

    // Only sender or receiver can download
    if (file.senderId.toString() !== userId.toString() && file.receiverId.toString() !== userId.toString()) {
      await logger.log('file', `Unauthorized download attempt fileId=${fileId} userId=${userId}`);
      return res.status(403).json({ message: 'Not authorized to download this file.' });
    }

    if (file.status !== 'complete') {
      return res.status(400).json({ message: 'File upload not complete.' });
    }

    await logger.log('file', `File download fileId=${fileId} userId=${userId}`);

    // Return file metadata and sorted chunks
    const sortedChunks = file.chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);

    res.json({
      fileId: file.fileId,
      fileName: file.fileName,
      fileSize: file.fileSize,
      mimeType: file.mimeType,
      totalChunks: file.totalChunks,
      chunks: sortedChunks.map(c => ({
        chunkIndex: c.chunkIndex,
        ciphertext: c.ciphertext,
        iv: c.iv,
        authTag: c.authTag,
      })),
    });
  } catch (error) {
    await logger.log('file', `File download error fileId=${fileId} error=${error.message}`);
    res.status(500).json({ message: 'Server error downloading file', error: error.message });
  }
});

module.exports = router;
