import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { getDecryptedPrivateKey } from '../services/indexedDbService'; // Import the IndexedDB service

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const userData = await login(username, password); // Perform login
      
      // Attempt to retrieve and decrypt private key after successful login
      // This is necessary for future cryptographic operations.
      try {
        const privateKeyJwk = await getDecryptedPrivateKey(userData._id, password);
        // console.log("Private key successfully retrieved and decrypted from IndexedDB:", privateKeyJwk);
        // In a real application, you might store this in a React context or state for use
        // by other components, but ensure it's not exposed globally.
        // For now, just logging to confirm retrieval.
      } catch (keyError) {
        console.error("Failed to retrieve or decrypt private key:", keyError);
        // This could happen if key wasn't stored (e.g., old user or registration failed partially)
        // or if password is wrong (but login passed)
        setError("Login successful, but failed to retrieve your private key. Please contact support.");
        // Consider forcing re-registration or a key recovery flow here in a production app.
        return; // Prevent navigation to home if key retrieval fails
      }

      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please check your credentials.');
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Welcome Back</h2>
          <p>Sign in to your secure messaging account</p>
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
              placeholder="Enter your username"
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
              placeholder="••••••••"
              required
            />
          </div>
          
          <button type="submit" className="btn-primary">
            Sign In
          </button>
        </form>
        
        <div className="auth-footer">
          Don't have an account? <Link to="/register">Create account</Link>
        </div>
      </div>
    </div>
  );
};

export default Login;
