/**
 * Replay Attack Demonstration Script
 * 
 * This script demonstrates:
 * 1. How replay attacks work
 * 2. How our system detects and prevents replay attacks using:
 *    - Nonces (unique message IDs)
 *    - Timestamps
 *    - Sequence numbers
 * 
 * EDUCATIONAL PURPOSE ONLY
 */

const axios = require('axios');

const API_URL = 'http://localhost:5000/api';

console.log('='.repeat(80));
console.log('REPLAY ATTACK DEMONSTRATION');
console.log('='.repeat(80));
console.log();

// Mock authentication tokens (in real scenario, these would be obtained through login)
let aliceToken = null;
let bobToken = null;

async function setup() {
    console.log('SETUP: Creating test users...');
    console.log('-'.repeat(80));

    try {
        // Register Alice
        const aliceRes = await axios.post(`${API_URL}/auth/register`, {
            username: `alice_replay_${Date.now()}`,
            password: 'testpassword123'
        });
        aliceToken = aliceRes.data.token;
        console.log('✓ Alice registered');

        // Register Bob
        const bobRes = await axios.post(`${API_URL}/auth/register`, {
            username: `bob_replay_${Date.now()}`,
            password: 'testpassword123'
        });
        bobToken = bobRes.data.token;
        console.log('✓ Bob registered');

        return { aliceId: aliceRes.data._id, bobId: bobRes.data._id };
    } catch (error) {
        console.error('Setup failed:', error.response?.data || error.message);
        process.exit(1);
    }
}

async function demonstrateReplayAttack(aliceId, bobId) {
    console.log();
    console.log('SCENARIO 1: Replay Attack with Duplicate Message ID (Nonce)');
    console.log('-'.repeat(80));

    // Legitimate message from Alice to Bob
    const legitimateMessage = {
        receiverId: bobId,
        ciphertext: 'base64encodedciphertext',
        iv: 'base64encodediv',
        authTag: 'base64encodedauthtag',
        messageId: `msg-${Date.now()}-unique123`,
        timestamp: new Date().toISOString(),
        sequenceNumber: 1
    };

    console.log('📡 Alice sends a legitimate message to Bob');
    console.log(`   Message ID: ${legitimateMessage.messageId}`);
    console.log(`   Sequence: ${legitimateMessage.sequenceNumber}`);
    console.log(`   Timestamp: ${legitimateMessage.timestamp}`);

    try {
        await axios.post(`${API_URL}/messages`, legitimateMessage, {
            headers: { Authorization: `Bearer ${aliceToken}` }
        });
        console.log('✓ Message sent successfully');
    } catch (error) {
        console.log('❌ Message failed:', error.response?.data?.message);
    }

    console.log();
    console.log('🔴 ATTACKER captures the message and tries to replay it...');

    // Attacker tries to replay the same message
    try {
        await axios.post(`${API_URL}/messages`, legitimateMessage, {
            headers: { Authorization: `Bearer ${aliceToken}` }
        });
        console.log('❌ VULNERABILITY: Replay attack succeeded!');
    } catch (error) {
        console.log('🛡️  REPLAY ATTACK BLOCKED!');
        console.log(`   Reason: ${error.response?.data?.message}`);
        console.log(`   Detection: ${error.response?.data?.reason || 'Duplicate message ID'}`);
    }

    console.log();
    console.log('SCENARIO 2: Replay Attack with Old Timestamp');
    console.log('-'.repeat(80));

    // Message with old timestamp
    const oldMessage = {
        receiverId: bobId,
        ciphertext: 'base64encodedciphertext2',
        iv: 'base64encodediv2',
        authTag: 'base64encodedauthtag2',
        messageId: `msg-${Date.now()}-unique456`,
        timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(), // 10 minutes old
        sequenceNumber: 2
    };

    console.log('🔴 ATTACKER tries to send a message with an old timestamp');
    console.log(`   Message ID: ${oldMessage.messageId}`);
    console.log(`   Timestamp: ${oldMessage.timestamp} (10 minutes old)`);

    try {
        await axios.post(`${API_URL}/messages`, oldMessage, {
            headers: { Authorization: `Bearer ${aliceToken}` }
        });
        console.log('❌ VULNERABILITY: Old message accepted!');
    } catch (error) {
        console.log('🛡️  REPLAY ATTACK BLOCKED!');
        console.log(`   Reason: ${error.response?.data?.message}`);
        console.log(`   Detection: ${error.response?.data?.reason || 'Expired timestamp'}`);
    }

    console.log();
    console.log('SCENARIO 3: Replay Attack with Out-of-Order Sequence Number');
    console.log('-'.repeat(80));

    // Send a message with sequence 10
    const futureMessage = {
        receiverId: bobId,
        ciphertext: 'base64encodedciphertext3',
        iv: 'base64encodediv3',
        authTag: 'base64encodedauthtag3',
        messageId: `msg-${Date.now()}-unique789`,
        timestamp: new Date().toISOString(),
        sequenceNumber: 10
    };

    console.log('📡 Alice sends a message with sequence number 10');

    try {
        await axios.post(`${API_URL}/messages`, futureMessage, {
            headers: { Authorization: `Bearer ${aliceToken}` }
        });
        console.log('✓ Message sent successfully');
    } catch (error) {
        console.log('❌ Message failed:', error.response?.data?.message);
    }

    // Now try to send an old sequence number
    const oldSequenceMessage = {
        receiverId: bobId,
        ciphertext: 'base64encodedciphertext4',
        iv: 'base64encodediv4',
        authTag: 'base64encodedauthtag4',
        messageId: `msg-${Date.now()}-unique101112`,
        timestamp: new Date().toISOString(),
        sequenceNumber: 5 // Old sequence number
    };

    console.log();
    console.log('🔴 ATTACKER tries to send a message with old sequence number 5');

    try {
        await axios.post(`${API_URL}/messages`, oldSequenceMessage, {
            headers: { Authorization: `Bearer ${aliceToken}` }
        });
        console.log('❌ VULNERABILITY: Old sequence accepted!');
    } catch (error) {
        console.log('🛡️  REPLAY ATTACK BLOCKED!');
        console.log(`   Reason: ${error.response?.data?.message}`);
        console.log(`   Detection: ${error.response?.data?.reason || 'Old sequence number'}`);
    }
}

async function main() {
    const { aliceId, bobId } = await setup();
    await demonstrateReplayAttack(aliceId, bobId);

    console.log();
    console.log('='.repeat(80));
    console.log('CONCLUSION');
    console.log('='.repeat(80));
    console.log();
    console.log('Our system prevents replay attacks using THREE mechanisms:');
    console.log();
    console.log('1. NONCES (Message IDs):');
    console.log('   ✅ Each message has a unique ID');
    console.log('   ✅ Duplicate IDs are rejected');
    console.log();
    console.log('2. TIMESTAMPS:');
    console.log('   ✅ Messages must be recent (within 5-minute window)');
    console.log('   ✅ Old messages are rejected');
    console.log();
    console.log('3. SEQUENCE NUMBERS:');
    console.log('   ✅ Messages are numbered sequentially per conversation');
    console.log('   ✅ Out-of-order or duplicate sequences are rejected');
    console.log();
    console.log('='.repeat(80));

    process.exit(0);
}

main().catch(error => {
    console.error('Demo failed:', error.message);
    process.exit(1);
});
