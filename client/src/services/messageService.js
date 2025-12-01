import axios from 'axios';

const API_URL = 'http://localhost:5000/api/messages';

// Helper to get authenticated config
const getAuthHeaders = () => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user || !user.token) {
    throw new Error('User not authenticated.');
  }
  return {
    headers: {
      Authorization: `Bearer ${user.token}`,
      'Content-Type': 'application/json',
    },
  };
};

/**
 * Sends an encrypted message.
 * @param {string} receiverId The ID of the recipient.
 * @param {string} ciphertext Base64 encoded encrypted message.
 * @param {string} iv Base64 encoded IV.
 * @param {string} authTag Base64 encoded authentication tag.
 * @param {number} sequenceNumber Sequence number for replay protection.
 * @returns {Promise<object>} The sent message object.
 */
const sendMessage = async (receiverId, ciphertext, iv, authTag, sequenceNumber) => {
  // Generate unique messageId (nonce)
  const messageId = `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  const payload = {
    receiverId,
    ciphertext,
    iv,
    authTag,
    messageId,
    timestamp: new Date().toISOString(), // Include timestamp for replay protection
    sequenceNumber,
  };
  const response = await axios.post(API_URL, payload, getAuthHeaders());
  return response.data;
};

/**
 * Fetches encrypted messages for a conversation with a specific peer.
 * @param {string} peerId The ID of the peer in the conversation.
 * @param {string|null} since Optional ISO timestamp to fetch messages after.
 * @returns {Promise<object[]>} An array of encrypted message objects.
 */
const getMessages = async (peerId, since = null) => {
  let url = `${API_URL}/${peerId}`;
  if (since) {
    url += `?since=${encodeURIComponent(since)}`;
  }
  const response = await axios.get(url, getAuthHeaders());
  return response.data;
};

const messageService = {
  sendMessage,
  getMessages,
};

export default messageService;
