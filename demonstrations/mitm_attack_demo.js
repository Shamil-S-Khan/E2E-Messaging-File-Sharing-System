/**
 * MITM (Man-in-the-Middle) Attack Demonstration Script
 * 
 * This script demonstrates:
 * 1. How MITM attacks work against unsigned Diffie-Hellman key exchange
 * 2. How digital signatures prevent MITM attacks in our system
 * 
 * EDUCATIONAL PURPOSE ONLY - DO NOT USE FOR MALICIOUS PURPOSES
 */

const crypto = require('crypto');

console.log('='.repeat(80));
console.log('MITM ATTACK DEMONSTRATION');
console.log('='.repeat(80));
console.log();

// ============================================================================
// SCENARIO 1: Diffie-Hellman WITHOUT Signatures (Vulnerable to MITM)
// ============================================================================

console.log('SCENARIO 1: Diffie-Hellman WITHOUT Digital Signatures');
console.log('-'.repeat(80));

// Alice generates her ECDH key pair
const aliceECDH = crypto.createECDH('prime256v1');
const alicePublicKey = aliceECDH.generateKeys();
console.log('✓ Alice generates ECDH key pair');
console.log(`  Alice's public key: ${alicePublicKey.toString('hex').substring(0, 32)}...`);

// Bob generates his ECDH key pair
const bobECDH = crypto.createECDH('prime256v1');
const bobPublicKey = bobECDH.generateKeys();
console.log('✓ Bob generates ECDH key pair');
console.log(`  Bob's public key: ${bobPublicKey.toString('hex').substring(0, 32)}...`);

console.log();
console.log('🚨 ATTACKER INTERCEPTS THE EXCHANGE!');
console.log();

// Attacker (Eve) generates her own ECDH key pair
const eveECDH = crypto.createECDH('prime256v1');
const evePublicKey = eveECDH.generateKeys();
console.log('✓ Eve (attacker) generates her own ECDH key pair');
console.log(`  Eve's public key: ${evePublicKey.toString('hex').substring(0, 32)}...`);

// Eve intercepts and replaces Alice's public key with her own
console.log();
console.log('📡 Alice → Bob: Sending public key...');
console.log('🔴 Eve intercepts and replaces Alice\'s key with her own!');
console.log('📡 Eve → Bob: Sending Eve\'s public key (pretending to be Alice)');

// Bob thinks he's deriving a shared secret with Alice, but it's actually with Eve
const bobSharedWithEve = bobECDH.computeSecret(evePublicKey);
console.log('✓ Bob derives shared secret (thinks it\'s with Alice, but it\'s with Eve)');

// Eve intercepts Bob's response and replaces it
console.log();
console.log('📡 Bob → Alice: Sending public key...');
console.log('🔴 Eve intercepts and replaces Bob\'s key with her own!');
console.log('📡 Eve → Alice: Sending Eve\'s public key (pretending to be Bob)');

// Alice thinks she's deriving a shared secret with Bob, but it's actually with Eve
const aliceSharedWithEve = aliceECDH.computeSecret(evePublicKey);
console.log('✓ Alice derives shared secret (thinks it\'s with Bob, but it\'s with Eve)');

// Eve can now derive shared secrets with both Alice and Bob
const eveSharedWithAlice = eveECDH.computeSecret(alicePublicKey);
const eveSharedWithBob = eveECDH.computeSecret(bobPublicKey);

console.log();
console.log('🎯 MITM ATTACK SUCCESSFUL!');
console.log('   Eve has established separate shared secrets with both Alice and Bob');
console.log('   Eve can now decrypt, read, modify, and re-encrypt all messages');
console.log(`   Alice's secret with Eve: ${aliceSharedWithEve.toString('hex').substring(0, 32)}...`);
console.log(`   Bob's secret with Eve: ${bobSharedWithEve.toString('hex').substring(0, 32)}...`);
console.log(`   Eve's secret with Alice: ${eveSharedWithAlice.toString('hex').substring(0, 32)}...`);
console.log(`   Eve's secret with Bob: ${eveSharedWithBob.toString('hex').substring(0, 32)}...`);

console.log();
console.log('💀 VULNERABILITY: Without authentication, Alice and Bob have no way to verify');
console.log('   that they are actually communicating with each other!');

console.log();
console.log('='.repeat(80));
console.log();

// ============================================================================
// SCENARIO 2: Diffie-Hellman WITH Digital Signatures (MITM Prevention)
// ============================================================================

console.log('SCENARIO 2: Diffie-Hellman WITH Digital Signatures (Our System)');
console.log('-'.repeat(80));

// Alice generates RSA key pair for signing
const aliceRSA = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
console.log('✓ Alice generates RSA key pair for signing');

// Bob generates RSA key pair for signing
const bobRSA = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
console.log('✓ Bob generates RSA key pair for signing');

// Alice generates new ECDH key pair
const aliceECDH2 = crypto.createECDH('prime256v1');
const alicePublicKey2 = aliceECDH2.generateKeys();
console.log('✓ Alice generates new ECDH key pair');

// Alice signs her ECDH public key with her RSA private key
const aliceSignature = crypto.sign('sha256', alicePublicKey2, {
    key: aliceRSA.privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
});
console.log('✓ Alice signs her ECDH public key with her RSA private key');
console.log(`  Signature: ${aliceSignature.toString('hex').substring(0, 32)}...`);

console.log();
console.log('📡 Alice → Bob: Sending ECDH public key + RSA signature');
console.log('🔴 Eve tries to intercept and replace the key...');

// Eve tries to replace Alice's key with her own
const eveECDH2 = crypto.createECDH('prime256v1');
const evePublicKey2 = eveECDH2.generateKeys();
console.log('✓ Eve generates her own ECDH key pair');
console.log('🔴 Eve sends her public key to Bob (pretending to be Alice)');

// Bob receives the message and verifies the signature
console.log();
console.log('✓ Bob receives the message and verifies the signature...');

try {
    // Bob tries to verify Eve's key with Alice's signature (this will fail!)
    const isValid = crypto.verify(
        'sha256',
        evePublicKey2,
        {
            key: aliceRSA.publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        },
        aliceSignature
    );

    if (!isValid) {
        console.log('🛡️  SIGNATURE VERIFICATION FAILED!');
        console.log('   Bob detects that the public key was tampered with');
        console.log('   Bob REJECTS the key exchange');
        console.log('   MITM attack PREVENTED!');
    }
} catch (error) {
    console.log('🛡️  SIGNATURE VERIFICATION FAILED!');
    console.log('   Bob detects that the public key was tampered with');
    console.log('   MITM attack PREVENTED!');
}

console.log();
console.log('✅ Now let\'s try with the LEGITIMATE signature:');

// Bob verifies Alice's REAL signature
const isLegitimate = crypto.verify(
    'sha256',
    alicePublicKey2,
    {
        key: aliceRSA.publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
    },
    aliceSignature
);

console.log(`✓ Bob verifies Alice's signature: ${isLegitimate ? 'VALID ✅' : 'INVALID ❌'}`);

if (isLegitimate) {
    console.log('✓ Bob accepts Alice\'s public key');
    console.log('✓ Secure key exchange proceeds...');

    // Bob generates his ECDH key pair and signs it
    const bobECDH2 = crypto.createECDH('prime256v1');
    const bobPublicKey2 = bobECDH2.generateKeys();
    const bobSignature = crypto.sign('sha256', bobPublicKey2, {
        key: bobRSA.privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
    });

    console.log('✓ Bob generates ECDH key pair and signs it');
    console.log('📡 Bob → Alice: Sending ECDH public key + RSA signature');

    // Alice verifies Bob's signature
    const isBobLegitimate = crypto.verify(
        'sha256',
        bobPublicKey2,
        {
            key: bobRSA.publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        },
        bobSignature
    );

    console.log(`✓ Alice verifies Bob's signature: ${isBobLegitimate ? 'VALID ✅' : 'INVALID ❌'}`);

    if (isBobLegitimate) {
        // Both parties derive the shared secret
        const aliceShared = aliceECDH2.computeSecret(bobPublicKey2);
        const bobShared = bobECDH2.computeSecret(alicePublicKey2);

        console.log();
        console.log('🎉 SECURE KEY EXCHANGE COMPLETED!');
        console.log(`   Alice's shared secret: ${aliceShared.toString('hex').substring(0, 32)}...`);
        console.log(`   Bob's shared secret: ${bobShared.toString('hex').substring(0, 32)}...`);
        console.log(`   Secrets match: ${aliceShared.equals(bobShared) ? 'YES ✅' : 'NO ❌'}`);
    }
}

console.log();
console.log('='.repeat(80));
console.log('CONCLUSION');
console.log('='.repeat(80));
console.log();
console.log('WITHOUT Signatures:');
console.log('  ❌ Vulnerable to MITM attacks');
console.log('  ❌ No way to verify identity');
console.log('  ❌ Attacker can intercept and decrypt all messages');
console.log();
console.log('WITH Signatures (Our System):');
console.log('  ✅ MITM attacks are detected and prevented');
console.log('  ✅ Cryptographic proof of identity');
console.log('  ✅ Tampered messages are rejected');
console.log('  ✅ End-to-end security guaranteed');
console.log();
console.log('='.repeat(80));
