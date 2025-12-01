# Security Demonstrations

This directory contains demonstration scripts for security attacks and defenses implemented in the Secure Messaging System.

## Prerequisites

- Node.js installed
- Server running on `http://localhost:5000`
- MongoDB connected

## Demonstrations

### 1. MITM (Man-in-the-Middle) Attack Demo

**File**: `mitm_attack_demo.js`

**Purpose**: Demonstrates how MITM attacks work against unsigned Diffie-Hellman and how digital signatures prevent them.

**Run**:
```bash
node demonstrations/mitm_attack_demo.js
```

**What it shows**:
- ✅ Scenario 1: DH without signatures (vulnerable)
- ✅ Scenario 2: DH with RSA signatures (protected)
- ✅ How Eve (attacker) can intercept and replace keys
- ✅ How signature verification detects tampering

**Expected Output**:
- MITM attack succeeds without signatures
- MITM attack fails with signatures
- Detailed logs showing the attack flow

---

### 2. Replay Attack Demo

**File**: `replay_attack_demo.js`

**Purpose**: Demonstrates how replay attacks work and how our system detects them.

**Run**:
```bash
node demonstrations/replay_attack_demo.js
```

**What it shows**:
- ✅ Nonce-based detection (duplicate message IDs)
- ✅ Timestamp-based detection (old messages)
- ✅ Sequence number detection (out-of-order messages)

**Expected Output**:
- Legitimate messages accepted
- Replayed messages rejected
- Detection reasons logged

---

## Attack Scenarios Demonstrated

### MITM Attack (Scenario 1 - Vulnerable)
```
Alice → Eve (thinks it's Bob) → Bob
  ↓                              ↓
Shared secret with Eve    Shared secret with Eve
```

### MITM Attack (Scenario 2 - Protected)
```
Alice → [Signed Key] → Bob
         ↓
    Eve intercepts
         ↓
    Signature invalid!
         ↓
    Attack BLOCKED ✅
```

### Replay Attack
```
1. Alice → Bob: Message (seq=1, id=abc, time=now)
2. Attacker captures message
3. Attacker → Bob: Same message (BLOCKED - duplicate ID)
4. Attacker → Bob: Old message (BLOCKED - expired timestamp)
5. Attacker → Bob: Old sequence (BLOCKED - sequence < last)
```

---

## Security Logs

After running the demonstrations, you can view security logs:

### Via API:
```bash
# Get all security logs
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:5000/api/security/logs

# Get replay attack logs
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:5000/api/security/events/replay_attack_detected

# Get statistics
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:5000/api/security/stats
```

### Via Admin Panel:
Navigate to `http://localhost:3000/admin/security` (if implemented)

---

## Educational Use Only

⚠️ **WARNING**: These demonstrations are for educational purposes only. Do not use these techniques for malicious purposes. Unauthorized access to computer systems is illegal.

---

## Report Screenshots

For your project report, capture screenshots of:

1. ✅ MITM demo output showing attack failure
2. ✅ Replay demo output showing detection
3. ✅ Security logs showing blocked attacks
4. ✅ Console logs from both client and server

---

## Troubleshooting

**Issue**: "Connection refused"
- **Solution**: Make sure the server is running on port 5000

**Issue**: "Authentication failed"
- **Solution**: The replay demo creates test users automatically

**Issue**: "Module not found"
- **Solution**: Run `npm install` in the server directory

---

## Additional Resources

- See `../server/services/replayDetector.js` for replay detection implementation
- See `../server/services/securityLogger.js` for logging implementation
- See `../client/src/components/KeyExchangeManager.jsx` for signature verification
