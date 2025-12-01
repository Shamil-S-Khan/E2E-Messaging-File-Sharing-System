import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { generateRSAKeyPair, exportKeyToJwk, exportPublicKeyToSpkiBase64 } from '../utils/cryptoUtils';
import { storeEncryptedPrivateKey } from '../services/indexedDbService';
import authService from '../services/authService'; // Ensure authService is imported

const Register = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { register, loadUserAndKeys } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // 1. Register user (Step 1)
      const userData = await register(username, password);
      
      // 2. Generate RSA Key Pair (Step 2)
      const keyPair = await generateRSAKeyPair();
      
      // 3. Export Public Key and upload to server (Step 2)
      const publicKeySpkiBase64 = await exportPublicKeyToSpkiBase64(keyPair.publicKey);
      await authService.uploadPublicKey(publicKeySpkiBase64); // Use authService for upload

      // 4. Export Private Key and store encrypted in IndexedDB (Step 2)
      const privateKeyJwk = await exportKeyToJwk(keyPair.privateKey);
      await storeEncryptedPrivateKey(userData._id, privateKeyJwk, password); // Use user ID from registration

      // 5. NOW load the keys into context, because they are safely in DB
      await loadUserAndKeys();

      navigate('/');
    } catch (err) {
      console.error('Registration or Key Generation/Storage failed:', err);
      setError(err.response?.data?.message || err.message || 'Registration failed. Try a different username.');
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Create Account</h2>
          <p>Join the secure messaging platform</p>
        </div>

        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              className="form-input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Choose a username"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              className="form-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a strong password"
              required
            />
          </div>

          <button type="submit" className="btn-primary">
            Create Account
          </button>
        </form>

        <div className="auth-footer">
          Already have an account? <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
};

export default Register;
