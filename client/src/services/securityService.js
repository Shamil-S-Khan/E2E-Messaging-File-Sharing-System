import axios from 'axios';

const API_URL = 'http://localhost:5000/api/messages';

// Helper to get authenticated config
const getAuthHeaders = () => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user || !user.token) {
    return null; // Not authenticated
  }
  return {
    headers: {
      Authorization: `Bearer ${user.token}`,
      'Content-Type': 'application/json',
    },
  };
};

/**
 * Reports a security event to the server for logging.
 * Call this when client-side security checks fail.
 * 
 * @param {string} eventType - One of: 'decryption_failed', 'invalid_signature', 
 *                             'key_exchange_failed', 'invalid_mac', 'tampered_message'
 * @param {object} details - Additional context about the event
 */
export const reportSecurityEvent = async (eventType, details = {}) => {
  const headers = getAuthHeaders();
  if (!headers) {
    console.warn('[Security] Cannot report event - not authenticated');
    return;
  }

  try {
    await axios.post(`${API_URL}/security-event`, { eventType, details }, headers);
    console.log(`[Security] Event reported: ${eventType}`);
  } catch (err) {
    // Don't throw - security reporting should be fire-and-forget
    console.error('[Security] Failed to report event:', err.message);
  }
};

/**
 * Wrapper for decryption that reports failures
 */
export const secureDecrypt = async (decryptFn, context = {}) => {
  try {
    return await decryptFn();
  } catch (err) {
    await reportSecurityEvent('decryption_failed', {
      error: err.message,
      ...context,
    });
    throw err; // Re-throw so caller knows it failed
  }
};

/**
 * Wrapper for signature verification that reports failures
 */
export const secureVerifySignature = async (verifyFn, context = {}) => {
  try {
    const isValid = await verifyFn();
    if (!isValid) {
      await reportSecurityEvent('invalid_signature', context);
    }
    return isValid;
  } catch (err) {
    await reportSecurityEvent('invalid_signature', {
      error: err.message,
      ...context,
    });
    throw err;
  }
};

/**
 * Wrapper for MAC verification that reports failures
 */
export const secureVerifyMac = async (verifyFn, context = {}) => {
  try {
    const isValid = await verifyFn();
    if (!isValid) {
      await reportSecurityEvent('invalid_mac', context);
    }
    return isValid;
  } catch (err) {
    await reportSecurityEvent('invalid_mac', {
      error: err.message,
      ...context,
    });
    throw err;
  }
};

const securityService = {
  reportSecurityEvent,
  secureDecrypt,
  secureVerifySignature,
  secureVerifyMac,
};

export default securityService;
