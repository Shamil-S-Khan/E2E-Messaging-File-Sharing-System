import React, { createContext, useState, useEffect, useContext, useCallback } from 'react';
import authService from '../services/authService';
import { getDecryptedPrivateKey, storeEncryptedSessionKey, getAllEncryptedSessionKeys, getDecryptedSessionKey } from '../services/indexedDbService';
import { importKeyFromJwk, importPublicKeyFromSpkiBase64, exportKeyToJwk } from '../utils/cryptoUtils';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rsaKeyPair, setRsaKeyPair] = useState(null); // Store user's RSA key pair (private is CryptoKey)
  const [sessionKeys, setSessionKeys] = useState({}); // Stores derived AES-GCM session keys {peerId: CryptoKey}

  const loadUserAndKeys = useCallback(async () => {
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      const userData = JSON.parse(storedUser);
      setUser(userData);

      // Attempt to load private key from IndexedDB
      try {
        const password = sessionStorage.getItem(`userPassword_${userData._id}`); // Temporarily stored password for key decryption
        if (password) {
          const privateKeyJwk = await getDecryptedPrivateKey(userData._id, password);

          // SANITIZE JWK: Remove key_ops and alg so we can re-purpose the key material
          // This allows us to use the same RSA key for both Encryption (RSA-OAEP) and Signing (RSASSA-PKCS1-v1_5)
          const { key_ops, alg, ...sanitizedJwk } = privateKeyJwk;

          // 1. Import as RSASSA-PKCS1-v1_5 for SIGNING (Step 3)
          const signingPrivateKey = await window.crypto.subtle.importKey(
            "jwk",
            sanitizedJwk,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            true,
            ["sign"]
          );

          // 2. Import as RSA-OAEP for DECRYPTION (Step 2/4)
          const decryptionPrivateKey = await window.crypto.subtle.importKey(
            "jwk",
            sanitizedJwk,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt", "unwrapKey"]
          );

          // Fetch our public key for verification
          let ourPublicKeySpkiBase64 = userData.publicKey;

          if (!ourPublicKeySpkiBase64) {
            try {
              const fullUserProfile = await authService.getProfile();
              ourPublicKeySpkiBase64 = fullUserProfile.publicKey;
            } catch (e) {
              console.warn("Could not fetch user profile for public key:", e);
            }
          }

          // Import Public Key for Verification (RSASSA)
          let verifyPublicKey = null;
          if (ourPublicKeySpkiBase64) {
            try {
              verifyPublicKey = await importPublicKeyFromSpkiBase64(ourPublicKeySpkiBase64);
            } catch (err) {
              console.error("Failed to import public key:", err);
            }
          }

          setRsaKeyPair({
            privateKey: signingPrivateKey,
            publicKey: verifyPublicKey,
            decryptionKey: decryptionPrivateKey
          });

          // --- LOAD SESSION KEYS ---
          try {
            const allSessionKeys = await getAllEncryptedSessionKeys();
            const loadedKeys = {};
            for (const keyData of allSessionKeys) {
              try {
                const decryptedKeyJwk = await getDecryptedSessionKey(keyData.peerId, password);
                if (decryptedKeyJwk) {
                  const importedKey = await importKeyFromJwk(decryptedKeyJwk, 'AES-GCM', ['encrypt', 'decrypt']);
                  loadedKeys[keyData.peerId] = importedKey;
                }
              } catch (e) {
                console.warn(`Could not load session key for peer ${keyData.peerId}`, e);
              }
            }
            setSessionKeys(loadedKeys);
          } catch (sessionKeyError) {
            console.error("Error loading session keys:", sessionKeyError);
          }

        } else {
          console.warn("Password not available in session storage to decrypt private key.");
        }
      } catch (keyError) {
        console.error("Error loading RSA private key:", keyError);
      }
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadUserAndKeys();
  }, [loadUserAndKeys]);

  const login = async (username, password) => {
    const userData = await authService.login(username, password);
    setUser(userData);
    sessionStorage.setItem(`userPassword_${userData._id}`, password); // Temporarily store password for key decryption

    // After login, load keys
    await loadUserAndKeys(); // Re-run to load RSA key pair
    return userData;
  };

  const register = async (username, password) => {
    const userData = await authService.register(username, password);
    setUser(userData);
    sessionStorage.setItem(`userPassword_${userData._id}`, password);
    // The Register component will generate keys, store them, and THEN call loadUserAndKeys() manually.
    return userData;
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    setRsaKeyPair(null);
    setSessionKeys({});
    // Remove password from session storage
    if (user) {
      sessionStorage.removeItem(`userPassword_${user._id}`);
    }
  };

  const addSessionKey = useCallback(async (peerId, key) => {
    setSessionKeys(prevKeys => ({
      ...prevKeys,
      [peerId]: key,
    }));

    // Persist to IndexedDB
    if (user) {
      const password = sessionStorage.getItem(`userPassword_${user._id}`);
      if (password) {
        try {
          const keyJwk = await exportKeyToJwk(key);
          await storeEncryptedSessionKey(peerId, keyJwk, password);
        } catch (err) {
          console.error("Failed to persist session key:", err);
        }
      }
    }
  }, [user]);

  const getSessionKey = useCallback((peerId) => {
    return sessionKeys[peerId];
  }, [sessionKeys]);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, rsaKeyPair, sessionKeys, addSessionKey, getSessionKey, loadUserAndKeys }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  return useContext(AuthContext);
};
