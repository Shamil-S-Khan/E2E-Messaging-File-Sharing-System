# Secure Messaging System - Information Security Project

A full-stack end-to-end encrypted messaging and file sharing application with custom key exchange protocol, replay attack protection, and comprehensive security logging.

## 🎯 Project Overview

This project implements a secure messaging system with the following security features:
- ✅ End-to-end encryption (AES-256-GCM)
- ✅ Custom key exchange protocol (ECDH + RSA signatures)
- ✅ Replay attack protection (nonces, timestamps, sequence numbers)
- ✅ MITM attack prevention (digital signatures)
- ✅ Secure key storage (client-side encrypted IndexedDB)
- ✅ Encrypted file sharing
- ✅ Comprehensive security logging and monitoring

## 📋 Requirements Fulfilled

| # | Requirement | Status |
|---|-------------|--------|
| 1 | User Authentication | ✅ Complete |
| 2 | Key Generation & Secure Storage | ✅ Complete |
| 3 | Secure Key Exchange Protocol | ✅ Complete |
| 4 | End-to-End Message Encryption | ✅ Complete |
| 5 | End-to-End File Sharing | ✅ Complete |
| 6 | Replay Attack Protection | ✅ Complete |
| 7 | MITM Attack Demonstration | ✅ Complete |
| 8 | Logging & Security Auditing | ✅ Complete |
| 9 | Threat Modeling (STRIDE) | ⚠️ Documentation Only |
| 10 | System Architecture & Docs | ⚠️ Documentation Only |

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (running on localhost:27017)
- npm or yarn

### Installation

1. **Clone the repository** (if applicable)
```bash
cd c:/Fast_Nukes_Universiry/Semester_7/Info_Sec/Project
```

2. **Install server dependencies**
```bash
cd server
npm install
```

3. **Install client dependencies**
```bash
cd ../client
npm install
```

4. **Set up environment variables**

Create `server/.env`:
```env
MONGO_URI=mongodb://localhost:27017/secure-messaging
JWT_SECRET=your_super_secret_jwt_key_here_change_this
PORT=5000
```

5. **Start MongoDB**
```bash
# Make sure MongoDB is running on localhost:27017
```

6. **Start the server**
```bash
cd server
npm start
# or
node index.js
```

7. **Start the client**
```bash
cd client
npm run dev
```

8. **Access the application**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000

## 🧪 Testing & Demonstrations

### Run Security Demonstrations

#### MITM Attack Demo
```bash
node demonstrations/mitm_attack_demo.js
```
**Shows**: How digital signatures prevent man-in-the-middle attacks

#### Replay Attack Demo
```bash
node demonstrations/replay_attack_demo.js
```
**Shows**: How nonces, timestamps, and sequence numbers prevent replay attacks

### Manual Testing Flow

1. **Register two users**
   - Open two browser windows (or use incognito)
   - Register as "Alice" in window 1
   - Register as "Bob" in window 2

2. **Initiate key exchange**
   - Alice: Click "Initiate Key Exchange" and select Bob
   - Bob: Click "Respond" to Alice's request
   - Wait for automatic confirmation and acknowledgement
   - Both should see "Key exchange completed successfully!"

3. **Send encrypted messages**
   - Click "Go to Chats" button
   - Select the peer from the sidebar
   - Type and send messages
   - Messages are encrypted end-to-end

4. **Share encrypted files**
   - Navigate to File Sharing section
   - Select recipient (must have session key)
   - Choose file and click "Encrypt & Send"
   - Recipient can download and decrypt

5. **View security logs**
   - Click "Security Logs" button on dashboard
   - View authentication attempts, key exchanges, replay attacks, etc.
   - Filter by event type or severity

## 🏗️ Architecture

### Technology Stack

**Frontend:**
- React 18 + Vite
- React Router v6
- Axios (HTTP client)
- IndexedDB (encrypted key storage)
- Web Crypto API (cryptographic operations)

**Backend:**
- Node.js + Express
- MongoDB + Mongoose
- JWT authentication
- bcrypt (password hashing)
- Node crypto (signature verification)

### Security Mechanisms

#### 1. Key Exchange Protocol
```
Alice                                    Bob
  |                                       |
  |-- ECDH PubKey + RSA Signature + Nonce -->
  |                                       |
  |                        Verify Signature
  |                                       |
  |<-- ECDH PubKey + RSA Signature + Nonce --
  |                                       |
Verify Signature                          |
  |                                       |
Both derive shared secret (ECDH)          |
Both derive session key (HKDF)            |
  |                                       |
  |-------- Confirmation MAC ------------>
  |                                       |
  |<------- Acknowledgement MAC ----------
  |                                       |
  ✓ Secure channel established            ✓
```

#### 2. Message Encryption
```
Plaintext → AES-256-GCM(SessionKey, IV) → Ciphertext + AuthTag
                                           ↓
                                    Store on server
                                           ↓
                                    Retrieve by peer
                                           ↓
Plaintext ← AES-256-GCM-Decrypt(SessionKey, IV, AuthTag) ← Ciphertext
```

#### 3. Replay Attack Protection
- **Nonce**: Unique message ID, duplicates rejected
- **Timestamp**: 5-minute validity window
- **Sequence Number**: Per-conversation counter, out-of-order rejected

## 📁 Project Structure

```
Project/
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── services/       # API services
│   │   ├── utils/          # Crypto utilities
│   │   └── context/        # Global state
│   └── package.json
├── server/                 # Express backend
│   ├── models/             # MongoDB schemas
│   ├── routes/             # API routes
│   ├── services/           # Business logic
│   ├── middleware/         # Auth middleware
│   └── index.js
├── demonstrations/         # Attack demonstrations
│   ├── mitm_attack_demo.js
│   ├── replay_attack_demo.js
│   └── README.md
├── tests/                  # Test scripts
└── IMPLEMENTATION_SUMMARY.md
```

## 🔐 Security Features

### Implemented Defenses

| Attack Vector | Defense Mechanism | Implementation |
|---------------|-------------------|----------------|
| Password Theft | bcrypt hashing (10 rounds) | `server/models/User.js` |
| Private Key Theft | Client-side encrypted storage | `client/src/services/indexedDbService.js` |
| MITM Attack | RSA digital signatures | `client/src/components/KeyExchangeManager.jsx` |
| Replay Attack | Nonces + Timestamps + Sequences | `server/services/replayDetector.js` |
| Message Tampering | AES-GCM authentication tags | `client/src/utils/cryptoUtils.js` |
| Eavesdropping | End-to-end encryption | All message/file routes |

### Cryptographic Primitives

- **RSA-2048**: User identity keys, signature generation/verification
- **ECDH (P-256)**: Ephemeral key exchange
- **AES-256-GCM**: Message and file encryption
- **HKDF**: Session key derivation
- **PBKDF2**: Password-based key derivation (100,000 iterations)
- **SHA-256**: Hashing and MAC generation

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/users` - List all users

### Key Exchange
- `POST /api/key-exchange/initiate` - Start key exchange
- `POST /api/key-exchange/respond` - Respond to request
- `POST /api/key-exchange/confirm` - Confirm exchange
- `POST /api/key-exchange/acknowledge` - Complete exchange
- `GET /api/key-exchange/sessions` - Get user sessions

### Messages
- `POST /api/messages` - Send encrypted message
- `GET /api/messages/:peerId` - Get messages with peer

### Files
- `POST /api/files/upload` - Upload encrypted file
- `GET /api/files` - List user files
- `GET /api/files/:fileId` - Download file

### Security Logs
- `GET /api/security/logs` - Get security logs
- `GET /api/security/stats` - Get statistics
- `GET /api/security/events/:eventType` - Get specific events

## 🐛 Troubleshooting

### Server won't start
- **Check MongoDB**: Ensure MongoDB is running
- **Check port**: Make sure port 5000 is not in use
- **Check .env**: Verify environment variables are set

### Client won't connect
- **Check server**: Ensure backend is running on port 5000
- **Check CORS**: CORS is enabled for all origins in development
- **Clear cache**: Try clearing browser cache and IndexedDB

### Key exchange fails
- **Refresh browser**: Close and reopen both browser windows
- **Clear IndexedDB**: Open DevTools → Application → IndexedDB → Delete
- **Check logs**: Look for errors in browser console and server console

### Messages not decrypting
- **Check session key**: Ensure key exchange completed successfully
- **Refresh page**: Session keys should persist after refresh
- **Re-exchange keys**: Try initiating a new key exchange

## 📝 For Report/Documentation

### Screenshots Needed
1. ✅ User registration and login
2. ✅ Key exchange process (all 4 steps)
3. ✅ Encrypted message sending/receiving
4. ✅ Encrypted file upload/download
5. ✅ Security logs dashboard
6. ✅ MITM demo output
7. ✅ Replay attack demo output
8. ✅ Browser DevTools showing encrypted data in IndexedDB

### Diagrams Needed
1. ⚠️ System architecture diagram
2. ⚠️ Key exchange protocol flow
3. ⚠️ Message encryption/decryption flow
4. ⚠️ Database schema (ER diagram)
5. ⚠️ STRIDE threat model

### Code to Highlight in Report
- Custom key exchange protocol: `client/src/components/KeyExchangeManager.jsx`
- Replay detection: `server/services/replayDetector.js`
- Security logging: `server/services/securityLogger.js`
- Encryption utilities: `client/src/utils/cryptoUtils.js`

## 🎓 Educational Use

This project is for educational purposes as part of an Information Security course. The implementations demonstrate:
- Secure communication protocols
- Cryptographic best practices
- Attack prevention techniques
- Security logging and monitoring

**⚠️ Warning**: This is a prototype for educational purposes. For production use, additional security hardening, code review, and penetration testing would be required.

## 📚 References

- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- ECDH: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
- AES-GCM: https://en.wikipedia.org/wiki/Galois/Counter_Mode
- STRIDE: https://en.wikipedia.org/wiki/STRIDE_(security)

## 👥 Team

[Add your team members' names here]

## 📄 License

Educational project - All rights reserved

---

**Last Updated**: December 2025
**Version**: 1.0.0
**Status**: Implementation Complete, Documentation Pending
