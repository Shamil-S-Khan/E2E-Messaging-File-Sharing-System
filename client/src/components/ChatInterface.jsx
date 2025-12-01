import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import messageService from '../services/messageService';
import authService from '../services/authService';
import { encryptWithAesGcm, decryptWithAesGcm } from '../utils/cryptoUtils';
import securityService from '../services/securityService';

const ChatInterface = () => {
  const { user, getSessionKey } = useAuth();
  const [peers, setPeers] = useState([]);
  const [selectedPeer, setSelectedPeer] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);

  // Track the timestamp of the last message we received to optimize polling
  const lastFetchedRef = useRef(null);

  // Track sequence numbers per conversation for replay protection
  const sequenceNumbersRef = useRef({});

  // Helper to convert string to Uint8Array
  const strToUint8 = (str) => new TextEncoder().encode(str);
  const uint8ToStr = (uint8) => new TextDecoder().decode(uint8);

  // Get next sequence number for a peer
  const getNextSequence = (peerId) => {
    if (!sequenceNumbersRef.current[peerId]) {
      sequenceNumbersRef.current[peerId] = 0;
    }
    sequenceNumbersRef.current[peerId]++;
    return sequenceNumbersRef.current[peerId];
  };

  // Scroll to bottom of messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    // Fetch all users to display as potential chat partners
    const fetchPeers = async () => {
      try {
        const allUsers = await authService.getUsers();
        // Filter out self, and only show users for whom a session key might exist
        const chatPeers = allUsers.filter(p => p._id !== user._id && getSessionKey(p._id));
        setPeers(chatPeers);
      } catch (err) {
        console.error('Failed to fetch chat peers:', err);
        setError('Failed to load chat partners.');
      }
    };

    if (user) {
      fetchPeers();
    }
  }, [user, getSessionKey]); // Rerun if session keys might have changed


  const fetchAndDecryptMessages = useCallback(async (peerId, isPolling = false) => {

    if (!isPolling) setError('');

    try {
      const sessionKey = getSessionKey(peerId);
      if (!sessionKey) {
        if (!isPolling) {
          setError('No session key established with this peer. Cannot decrypt messages.');
          setMessages([]);
        }
        return;
      }

      // If polling, ask for messages since the last one we have
      const since = isPolling ? lastFetchedRef.current : null;

      const encryptedMessages = await messageService.getMessages(peerId, since);

      if (encryptedMessages.length === 0) {
        return; // No new messages
      }

      const decryptedMessages = await Promise.all(
        encryptedMessages.map(async (msg) => {
          try {
            const decryptedContent = await decryptWithAesGcm(
              sessionKey,
              msg.iv,
              msg.ciphertext,
              msg.authTag
            );
            return { ...msg, decryptedContent: uint8ToStr(decryptedContent) };
          } catch (decryptionError) {
            console.error('Decryption failed for message:', msg.messageId, decryptionError);
            // Report security event for decryption failure
            securityService.reportSecurityEvent('decryption_failure', {
              messageId: msg.messageId,
              senderId: msg.senderId?._id || msg.senderId,
              error: decryptionError.message
            });
            return { ...msg, decryptedContent: '[Decryption Failed]' }; // Show placeholder on failure
          }
        })
      );

      if (isPolling) {
        // Append new messages
        setMessages(prev => {
          // Deduplicate based on messageId just in case
          const existingIds = new Set(prev.map(m => m.messageId));
          const uniqueNew = decryptedMessages.filter(m => !existingIds.has(m.messageId));
          return [...prev, ...uniqueNew];
        });
      } else {
        // Initial load: replace all
        setMessages(decryptedMessages);
      }

      // Update lastFetchedRef to the timestamp of the newest message
      if (decryptedMessages.length > 0) {
        const newestMsg = decryptedMessages[decryptedMessages.length - 1];
        lastFetchedRef.current = newestMsg.timestamp;
        scrollToBottom();
      }

    } catch (err) {
      console.error('Error fetching or decrypting messages:', err);
      if (!isPolling) setError('Failed to load messages.');
    }
  }, [getSessionKey]);


  useEffect(() => {
    if (selectedPeer) {
      // Reset state for new peer
      setMessages([]);
      lastFetchedRef.current = null;

      // Initial fetch
      fetchAndDecryptMessages(selectedPeer._id, false);

      // Implement polling for new messages (similar to key exchange manager)
      const messagePollingInterval = setInterval(() => {
        fetchAndDecryptMessages(selectedPeer._id, true);
      }, 3000); // Poll every 3 seconds

      return () => clearInterval(messagePollingInterval);
    }
  }, [selectedPeer, fetchAndDecryptMessages]);


  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim() || !selectedPeer) return;

    setError('');
    try {
      const sessionKey = getSessionKey(selectedPeer._id);
      if (!sessionKey) {
        setError('No session key established with this peer. Cannot send message.');
        return;
      }

      // Encrypt message
      const encryptedData = await encryptWithAesGcm(sessionKey, strToUint8(newMessage));

      // Get next sequence number for this conversation
      const sequenceNumber = getNextSequence(selectedPeer._id);

      // Send to backend with sequence number
      await messageService.sendMessage(
        selectedPeer._id,
        encryptedData.ciphertext,
        encryptedData.iv,
        encryptedData.tag,
        sequenceNumber
      );

      setNewMessage('');
      // Immediately fetch new messages (which should include the one we just sent)
      fetchAndDecryptMessages(selectedPeer._id, true);
    } catch (err) {
      console.error('Error sending message:', err);
      setError('Failed to send message.');
    }
  };


  if (!user) {
    return <div className="card" style={{ marginTop: '2rem' }}>Loading user data...</div>;
  }


  return (
    <div className="chat-container">
      <div className="sidebar card">
        <h3>Conversations</h3>
        {peers.length === 0 ? (
          <p style={{ fontSize: '0.9rem', color: '#6b7280' }}>
            No chat partners found with established session keys.
            Please initiate a key exchange.
          </p>
        ) : (
          <ul className="peer-list">
            {peers.map(peer => (
              <li
                key={peer._id}
                className={`peer-item ${selectedPeer?._id === peer._id ? 'active' : ''}`}
                onClick={() => setSelectedPeer(peer)}
              >
                {peer.username}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="chat-main card">
        {!selectedPeer ? (
          <div className="chat-placeholder">
            Select a conversation to start chatting securely.
          </div>
        ) : (
          <>
            <div className="chat-header">
              <h4>Chatting with {selectedPeer.username}</h4>
            </div>
            <div className="messages-area">
              {messages.length === 0 ? (
                <p className="no-messages">No messages yet. Start the conversation!</p>
              ) : (
                messages.map((msg) => (
                  <div key={msg.messageId} className={`message-bubble ${msg.senderId._id === user._id ? 'self' : 'peer'}`}>
                    <div className="message-content">
                      <span className="message-sender">{msg.senderId.username}: </span>
                      {msg.decryptedContent}
                    </div>
                    <span className="message-time">{new Date(msg.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>
            {error && <div className="error-message" style={{ marginBottom: '1rem' }}>{error}</div>}
            <form onSubmit={handleSendMessage} className="message-input-form">
              <input
                type="text"
                className="form-input"
                placeholder="Type your secure message..."
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                disabled={!getSessionKey(selectedPeer._id)}
              />
              <button type="submit" className="btn-primary" disabled={!getSessionKey(selectedPeer._id)}>
                Send
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
};

export default ChatInterface;
