import { describe, it, expect } from 'vitest';
import { FreebirdClient } from '../src/index';

describe('Freebird Docker Integration', () => {
  // Configuration matching your Docker Compose setup
  const config = {
    issuerUrl: 'http://127.0.0.1:8081',
    verifierUrl: 'http://127.0.0.1:8082'
  };

  it('should perform the full VOPRF flow', async () => {
    console.log(`\n🚀 Connecting to Issuer at ${config.issuerUrl}...`);
    
    const client = new FreebirdClient(config);

    // 1. Initialization (Fetches Metadata)
    await client.init();
    console.log('✅ Metadata fetched successfully');

    // 2. Token Issuance
    // Note: We assume SYBIL_RESISTANCE=none as configured in your docker-compose
    console.log('🔄 Requesting anonymous token...');
    const token = await client.issueToken();
    
    expect(token).toBeDefined();
    expect(token.tokenValue).toBeTypeOf('string');
    expect(token.tokenValue.length).toBeGreaterThan(0);
    expect(token.expiration).toBeGreaterThan(Date.now() / 1000);
    
    console.log(`✅ Token issued!`);
    console.log(`   Value: ${token.tokenValue.substring(0, 20)}...`);
    console.log(`   Expires: ${new Date(token.expiration * 1000).toISOString()}`);

    // 3. Verification
    console.log('🔍 Verifying token with Verifier service...');
    const isValid = await client.verifyToken(token);
    
    expect(isValid).toBe(true);
    console.log('✅ Token verified successfully!');
  });

  it('should reject an invalid token', async () => {
    const client = new FreebirdClient(config);
    
    // Create a fake token
    const fakeToken = {
      tokenValue: 'invalid_base64_string_that_is_not_a_token',
      expiration: Math.floor(Date.now() / 1000) + 3600,
      issuerId: 'issuer:docker:v1'
    };

    const isValid = await client.verifyToken(fakeToken);
    expect(isValid).toBe(false);
    console.log('✅ Invalid token correctly rejected');
  });
});