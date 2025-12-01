import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import authService from '../services/authService';
import keyExchangeService from '../services/keyExchangeService';
import { importPublicKeyFromSpkiBase64, importKeyFromJwk, exportKeyToJwk, deriveSharedSecret, deriveSessionKey as cryptoDeriveSessionKey, verifySignature, createMac, verifyMac } from '../utils/cryptoUtils';
import securityService from '../services/securityService';

// Helper to convert string to Uint8Array
const strToUint8 = (str) => new TextEncoder().encode(str);

const KeyExchangeManager = () => {
  const { user, rsaKeyPair, addSessionKey, getSessionKey } = useAuth();
  const [availableUsers, setAvailableUsers] = useState([]);
  const [selectedPeer, setSelectedPeer] = useState(null);
  const [status, setStatus] = useState('idle'); // idle, initiating, awaiting_response, responding, awaiting_confirmation, confirming, acknowledging, completed, failed
  const [message, setMessage] = useState('');
  const [activeSession, setActiveSession] = useState(null); // Stores the current session being processed
  const [myEcdhKeyPair, setMyEcdhKeyPair] = useState(null); // Our ECDH key pair for the active session
  const [myNonce, setMyNonce] = useState(null); // Our nonce for the active session

  const pollingIntervalRef = useRef(null);

  // --- Utility Functions ---
  const getPeerRsaPublicKey = useCallback(async (peerId) => {
    const users = await authService.getUsers();
    const peer = users.find(u => u._id === peerId);
    if (!peer || !peer.publicKey) {
      throw new Error(`Peer ${peerId} not found or public key missing.`);
    }
    return importPublicKeyFromSpkiBase64(peer.publicKey);
  }, []);

  // --- Protocol Step Handlers ---
  const aliceDeriveAndConfirm = useCallback(async (session) => {
    try {
      // Use local state selectedPeer if available, or derive from session data
      const peerId = session.responderId._id || session.responderId;
      const peerUsername = session.responderId.username || "Peer"; // Fallback

      if (!rsaKeyPair || !myEcdhKeyPair || !myNonce || !session.responderEcdhPublicKey || !session.responderSignature || !session.responderTimestamp) {
        throw new Error("Missing data for Alice's confirmation.");
      }

      // 1. Verify Bob's signature
      const peerRsaPublicKey = await getPeerRsaPublicKey(peerId);
      const dataSignedByBob = strToUint8(session.responderEcdhPublicKey + session.responderTimestamp);
      const isBobSignatureValid = await verifySignature(peerRsaPublicKey, session.responderSignature, dataSignedByBob);
      if (!isBobSignatureValid) {
        // Report security event for invalid signature
        securityService.reportSecurityEvent('invalid_signature', {
          sessionId: session._id,
          peerId: peerId,
          role: 'responder',
          message: "Bob's signature verification failed"
        });
        throw new Error("Bob's signature is invalid. MITM attack possible.");
      }

      // 2. Derive shared secret
      const responderEcdhPublicKey = await importKeyFromJwk(JSON.parse(session.responderEcdhPublicKey), 'ECDH', []);
      const sharedSecretAlice = await deriveSharedSecret(myEcdhKeyPair.privateKey, responderEcdhPublicKey);

      // 3. Derive session key
      const nonceB = Uint8Array.from(atob(session.nonceB), c => c.charCodeAt(0));
      const sessionKey = await cryptoDeriveSessionKey(sharedSecretAlice, myNonce, nonceB);
      addSessionKey(peerId, sessionKey); // Store session key

      // 4. Send confirmation
      await keyExchangeService.confirmKeyExchange(session._id, sessionKey, myNonce);
      setActiveSession({ ...session, status: 'confirmed' });
      setStatus('confirming');
      setMessage(`Alice confirmed key exchange with ${peerUsername}.`);
    } catch (error) {
      console.error("Alice's confirmation failed:", error);
      setMessage(`Alice's confirmation failed: ${error.message}`);
      setStatus('failed');
    }
  }, [rsaKeyPair, myEcdhKeyPair, myNonce, selectedPeer, addSessionKey, getPeerRsaPublicKey, keyExchangeService]);


  const bobVerifyAndAcknowledge = useCallback(async (session) => {
    try {
      // Derive initiator ID robustly
      const initiatorId = session.initiatorId._id || session.initiatorId;
      const initiatorUsername = session.initiatorId.username || "Peer";

      console.log('[DEBUG] Bob acknowledging - myEcdhKeyPair:', !!myEcdhKeyPair, 'myNonce:', !!myNonce);

      // Try to restore ephemeral state from sessionStorage if missing
      let ecdhKeyPair = myEcdhKeyPair;
      let nonce = myNonce;
      if ((!ecdhKeyPair || !nonce) && session._id) {
        console.log('[DEBUG] Attempting to restore ephemeral state from sessionStorage');
        try {
          const storedState = sessionStorage.getItem(`keyExchange_${session._id}`);
          if (storedState) {
            const { ecdhPrivateKey, ecdhPublicKey, nonce: storedNonce } = JSON.parse(storedState);
            // Import ECDH keys
            const privateKey = await importKeyFromJwk(ecdhPrivateKey, 'ECDH', ['deriveKey']);
            const publicKey = await importKeyFromJwk(ecdhPublicKey, 'ECDH', []);
            ecdhKeyPair = { privateKey, publicKey };
            nonce = Uint8Array.from(atob(storedNonce), c => c.charCodeAt(0));
            // Restore state
            setMyEcdhKeyPair(ecdhKeyPair);
            setMyNonce(nonce);
            console.log('[DEBUG] Successfully restored ephemeral state');
          }
        } catch (restoreError) {
          console.error('[DEBUG] Failed to restore ephemeral state:', restoreError);
        }
      }

      if (!rsaKeyPair || !ecdhKeyPair || !nonce || !session.initiatorEcdhPublicKey || !session.confirmationMac || !session.nonceA) {
        console.error('[DEBUG] Missing data:', {
          rsaKeyPair: !!rsaKeyPair,
          myEcdhKeyPair: !!ecdhKeyPair,
          myNonce: !!nonce,
          initiatorEcdhPublicKey: !!session.initiatorEcdhPublicKey,
          confirmationMac: !!session.confirmationMac,
          nonceA: !!session.nonceA
        });
        throw new Error("Missing data for Bob's acknowledgement.");
      }

      const sessionKey = getSessionKey(initiatorId);
      if (!sessionKey) {
        throw new Error("Session key not found for verification.");
      }

      // 3. Verify Alice's confirmation MAC
      const isMacValid = await verifyMac(sessionKey, session.confirmationMac, "CONFIRMED");
      if (!isMacValid) {
        // Report security event for invalid MAC
        securityService.reportSecurityEvent('invalid_mac', {
          sessionId: session._id,
          initiatorId: initiatorId,
          message: "Alice's confirmation MAC verification failed"
        });
        throw new Error("Alice's confirmation MAC is invalid. Key exchange failed.");
      }

      // 4. Send acknowledgement
      await keyExchangeService.acknowledgeKeyExchange(session, sessionKey, nonce);

      // Clean up sessionStorage
      sessionStorage.removeItem(`keyExchange_${session._id}`);

      setActiveSession({ ...session, status: 'completed' });
      setStatus('acknowledging');
      setMessage(`Bob acknowledged key exchange with ${initiatorUsername}. Key exchange completed.`);
    } catch (error) {
      console.error("Bob's acknowledgement failed:", error);
      setMessage(`Bob's acknowledgement failed: ${error.message}`);
      setStatus('failed');
    }
  }, [rsaKeyPair, myEcdhKeyPair, myNonce, getSessionKey, keyExchangeService]);

  const handleRespond = useCallback(async (session) => {
    if (!rsaKeyPair || !rsaKeyPair.privateKey || !session.initiatorId) {
      setMessage('RSA Private Key not loaded or session data incomplete.');
      return;
    }
    // Set selectedPeer for consistency, though activeSession drives logic
    setSelectedPeer(session.initiatorId);
    setStatus('responding');
    setMessage(`Responding to key exchange from ${session.initiatorId.username}...`);

    try {
      const initiatorRsaPublicKey = await getPeerRsaPublicKey(session.initiatorId._id);

      // 1. Verify Alice's signature (initiator)
      const initiatorEcdhPublicKeyJwkStr = session.initiatorEcdhPublicKey;
      const initiatorTimestamp = session.initiatorTimestamp;
      const initiatorSignature = session.initiatorSignature;
      const nonceA = Uint8Array.from(atob(session.nonceA), c => c.charCodeAt(0));

      const dataSignedByAlice = strToUint8(initiatorEcdhPublicKeyJwkStr + initiatorTimestamp);
      const isAliceSignatureValid = await verifySignature(initiatorRsaPublicKey, initiatorSignature, dataSignedByAlice);

      if (!isAliceSignatureValid) {
        // Report security event for invalid signature
        securityService.reportSecurityEvent('invalid_signature', {
          sessionId: session._id,
          peerId: session.initiatorId._id,
          role: 'initiator',
          message: "Alice's signature verification failed"
        });
        throw new Error("Alice's signature is invalid. MITM attack possible.");
      }

      // 2. Respond to Key Exchange (Bob's side)
      const { ecdhKeyPair, sessionKey, nonceB } = await keyExchangeService.respondToKeyExchange(
        { ...session, _id: session._id },
        rsaKeyPair,
        user._id,
        session.initiatorId.publicKey
      );

      setMyEcdhKeyPair(ecdhKeyPair);
      setMyNonce(nonceB);
      addSessionKey(session.initiatorId._id, sessionKey);

      // Store ephemeral state in sessionStorage for recovery
      try {
        const ecdhPrivateKeyJwk = await exportKeyToJwk(ecdhKeyPair.privateKey);
        const ecdhPublicKeyJwk = await exportKeyToJwk(ecdhKeyPair.publicKey);
        sessionStorage.setItem(`keyExchange_${session._id}`, JSON.stringify({
          ecdhPrivateKey: ecdhPrivateKeyJwk,
          ecdhPublicKey: ecdhPublicKeyJwk,
          nonce: btoa(String.fromCharCode(...nonceB)),
          sessionId: session._id
        }));
      } catch (storageError) {
        console.warn('Failed to store ephemeral key exchange state:', storageError);
      }

      setActiveSession({ ...session, status: 'responded' });
      setStatus('awaiting_confirmation');
      setMessage(`Responded to ${session.initiatorId.username}. Awaiting confirmation...`);
    } catch (error) {
      console.error('Response failed:', error);
      setMessage(`Failed to respond to key exchange: ${error.message}`);
      setStatus('failed');
      setActiveSession(null);
      setMyEcdhKeyPair(null);
      setMyNonce(null);
    }
  }, [user, rsaKeyPair, addSessionKey, getPeerRsaPublicKey, keyExchangeService]);


  // --- Polling for Session Updates ---
  const pollForSessionUpdates = useCallback(async () => {
    if (!user || !rsaKeyPair) return;

    try {
      const allMySessions = await keyExchangeService.getMySessions();
      // console.log('Polling sessions:', allMySessions); // Debug log

      for (const session of allMySessions) {
        // Check ID matching carefully (handle both populated object and string ID)
        const sessionResponderId = session.responderId._id || session.responderId;
        const sessionInitiatorId = session.initiatorId._id || session.initiatorId;

        // console.log(`Evaluating session ${session._id}: status=${session.status}, role=${sessionResponderId === user._id ? 'Responder' : 'Initiator'}`);

        // Bob receives initiation from Alice
        if (sessionResponderId === user._id && session.status === 'initiated') {
          // Only set as new if we don't have this session yet OR if status changed
          if (!activeSession || activeSession._id !== session._id || activeSession.status !== session.status) {
            setActiveSession(session);
            setMessage(`Incoming key exchange from ${session.initiatorId.username}.`);
            setStatus('awaiting_response_action');
            return;
          }
        }
        // Alice receives response from Bob
        else if (sessionInitiatorId === user._id && session.status === 'responded') {
          // Check if this is a NEW status update (session status changed from 'initiated' to 'responded')
          if (!activeSession || activeSession._id !== session._id || activeSession.status !== 'responded') {
            setActiveSession(session);
            setMessage(`Key exchange with ${session.responderId.username} responded. Confirming...`);
            await aliceDeriveAndConfirm(session);
            return;
          }
        }
        // Bob receives confirmation from Alice
        else if (sessionResponderId === user._id && session.status === 'confirmed') {
          // Check if this is a NEW status update
          if (!activeSession || activeSession._id !== session._id || activeSession.status !== 'confirmed') {
            setActiveSession(session);
            setMessage(`Key exchange with ${session.initiatorId.username} confirmed. Acknowledging...`);
            await bobVerifyAndAcknowledge(session);
            return;
          }
        }
        // Either party sees completion
        else if (session.status === 'completed') {
          if (activeSession && activeSession._id === session._id && activeSession.status !== 'completed') {
            setStatus('completed');
            setMessage('Key exchange completed successfully!');
            setActiveSession(null);
            setMyEcdhKeyPair(null);
            setMyNonce(null);
            clearInterval(pollingIntervalRef.current);
          }
        }
      }
    } catch (error) {
      console.error('Error polling for session updates:', error);
    }
  }, [user, rsaKeyPair, activeSession, myEcdhKeyPair, myNonce, aliceDeriveAndConfirm, bobVerifyAndAcknowledge, getSessionKey, addSessionKey]);


  useEffect(() => {
    // Poll if idle (looking for new requests) OR if we are in the middle of a handshake waiting for the other party
    const activeStates = ['idle', 'awaiting_response', 'awaiting_confirmation', 'responding', 'confirming', 'acknowledging', 'awaiting_response_action'];
    const shouldPoll = user && rsaKeyPair && activeStates.includes(status);

    if (shouldPoll) {
      pollingIntervalRef.current = setInterval(pollForSessionUpdates, 3000);
    } else {
      clearInterval(pollingIntervalRef.current);
    }
    return () => clearInterval(pollingIntervalRef.current);
  }, [user, rsaKeyPair, status, pollForSessionUpdates]);

  // --- Initial Data Fetch ---
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const users = await authService.getUsers();
        setAvailableUsers(users);
      } catch (error) {
        console.error('Failed to fetch available users:', error);
        setMessage('Failed to load users for key exchange.');
      }
    };
    if (user) {
      fetchUsers();
    }
  }, [user]);

  const handleInitiate = async (peer) => {
    if (!rsaKeyPair || !rsaKeyPair.privateKey) {
      setMessage('RSA Private Key not loaded. Please log in again.');
      return;
    }
    setSelectedPeer(peer);
    setStatus('initiating');
    setMessage(`Initiating key exchange with ${peer.username}...`);

    try {
      const { sessionId, ecdhKeyPair, nonceA } = await keyExchangeService.initiateKeyExchange(peer._id, rsaKeyPair);
      setMyEcdhKeyPair(ecdhKeyPair);
      setMyNonce(nonceA);
      setActiveSession({ _id: sessionId, initiatorId: user._id, responderId: peer._id, status: 'initiated', initiatorId: { username: user.username } });
      setStatus('awaiting_response');
      setMessage(`Initiated with ${peer.username}. Awaiting response...`);
    } catch (error) {
      console.error('Initiation failed:', error);
      setMessage(`Failed to initiate key exchange: ${error.message}`);
      setStatus('failed');
      setActiveSession(null);
      setMyEcdhKeyPair(null);
      setMyNonce(null);
    }
  };

  // --- Render Logic ---
  if (!user || !rsaKeyPair) {
    return <div className="card" style={{ marginTop: '2rem' }}>Loading user data or RSA keys...</div>;
  }

  const myUserId = user._id;
  const selectableUsers = availableUsers.filter(u => u._id !== myUserId && u.publicKey);

  // Safe accessors for current peer info
  const currentPeerId = selectedPeer?._id ||
    (activeSession?.initiatorId._id === myUserId ? activeSession?.responderId?._id : activeSession?.initiatorId?._id);

  const currentPeerUsername = selectedPeer?.username ||
    (activeSession?.initiatorId._id === myUserId ? activeSession?.responderId?.username : activeSession?.initiatorId?.username) ||
    "Unknown User";

  return (
    <div className="card" style={{ marginTop: '2rem' }}>
      <h3>🔑 Key Exchange</h3>
      <p style={{ color: '#6b7280', marginBottom: '1rem', fontSize: '0.9rem' }}>
        Establish secure session keys with other users for encrypted messaging.
      </p>

      {message && (
        <div className={`${status === 'completed' || status === 'acknowledging' ? 'success-message' : status === 'failed' ? 'error-message' : 'info-message'}`} style={{ marginBottom: '1rem', padding: '0.75rem', borderRadius: '6px' }}>
          {message}
        </div>
      )}

      {(status === 'idle' || status === 'awaiting_response_action') && (
        <>
          {/* Initiate New Exchange */}
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>Start New Exchange</h4>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <select
                className="form-input"
                value={selectedPeer?._id || ''}
                onChange={(e) => setSelectedPeer(selectableUsers.find(u => u._id === e.target.value))}
                style={{ flex: 1, minWidth: '200px' }}
              >
                <option value="">-- Select User --</option>
                {selectableUsers.map((u) => (
                  <option key={u._id} value={u._id}>
                    {u.username}
                  </option>
                ))}
              </select>
              <button
                className="btn-primary"
                onClick={() => selectedPeer && handleInitiate(selectedPeer)}
                disabled={!selectedPeer || status !== 'idle'}
                style={{ whiteSpace: 'nowrap' }}
              >
                Initiate Exchange
              </button>
            </div>
            {selectableUsers.length === 0 && <p style={{ color: '#ef4444', fontSize: '0.85rem', marginTop: '0.5rem' }}>No users available. Register another user first.</p>}
          </div>

          {/* Incoming Requests */}
          {activeSession && (activeSession.responderId._id || activeSession.responderId) === myUserId && activeSession.status === 'initiated' && status === 'awaiting_response_action' && (
            <div style={{ padding: '1rem', background: '#fef3c7', borderRadius: '6px', border: '1px solid #fbbf24' }}>
              <h4 style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>📨 Incoming Request</h4>
              <p style={{ marginBottom: '0.75rem' }}>
                <strong>{activeSession.initiatorId.username}</strong> wants to establish a secure connection
              </p>
              <button className="btn-primary" onClick={() => handleRespond(activeSession)}>
                Accept & Respond
              </button>
            </div>
          )}
        </>
      )}

      {/* Ongoing Exchange Status */}
      {(status !== 'idle' && status !== 'completed' && status !== 'failed' && activeSession) && (
        <div style={{ padding: '1rem', background: '#e0f2fe', borderRadius: '6px', border: '1px solid #3b82f6' }}>
          <h4 style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>⏳ Exchange in Progress</h4>
          <p style={{ fontSize: '0.9rem' }}>
            <strong>{currentPeerUsername}</strong> • {status.replace(/_/g, ' ')}
          </p>
        </div>
      )}

      {/* Reset Button */}
      {(status === 'failed' || status === 'completed') && (
        <button className="btn-secondary" onClick={() => {
          setStatus('idle');
          setMessage('');
          setActiveSession(null);
          setSelectedPeer(null);
          setMyEcdhKeyPair(null);
          setMyNonce(null);
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = setInterval(pollForSessionUpdates, 3000);
        }} style={{ marginTop: '1rem' }}>
          New Exchange
        </button>
      )}

      {/* Success Indicator */}
      {currentPeerId && getSessionKey(currentPeerId) && (
        <div style={{ marginTop: '1rem', padding: '0.75rem', background: '#d4edda', borderRadius: '6px', border: '1px solid #28a745' }}>
          <p style={{ margin: 0, fontSize: '0.9rem' }}>
            ✅ Secure session established with <strong>{currentPeerUsername}</strong>
          </p>
        </div>
      )}
    </div>
  );
};

export default KeyExchangeManager;
