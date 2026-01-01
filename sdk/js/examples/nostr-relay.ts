import { WebSocketServer, WebSocket } from 'ws';
import { FreebirdClient } from '../src/index';

// Configuration
const PORT = 8080;
const ISSUER_URL = 'http://127.0.0.1:8081';
const VERIFIER_URL = 'http://127.0.0.1:8082';

// Initialize Freebird Client (used here for verification)
const freebird = new FreebirdClient({ issuerUrl: ISSUER_URL, verifierUrl: VERIFIER_URL });

const wss = new WebSocketServer({ port: PORT });

console.log(`
🕊️  NOSTR RELAY SIMULATOR
    Listening on ws://localhost:${PORT}
    Requiring Freebird tokens for write access
`);

wss.on('connection', (ws: WebSocket) => {
  const challenge = crypto.randomUUID();
  let isAuthenticated = false;

  console.log(`[${challenge}] New connection`);

  // 1. Send Challenge immediately on connection
  // We use a custom prefix to signal Freebird support
  ws.send(JSON.stringify(['AUTH', `freebird:v1:${challenge}`]));

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      const type = msg[0];

      // Handle AUTH response
      if (type === 'AUTH') {
        await handleAuth(ws, msg, challenge);
        return;
      }

      // Handle EVENT (Publishing)
      if (type === 'EVENT') {
        if (!isAuthenticated) {
          ws.send(JSON.stringify(['OK', msg[1].id, false, 'restricted: auth required']));
          console.log(`[${challenge}] ❌ Rejected event (unauthenticated)`);
          return;
        }
        
        ws.send(JSON.stringify(['OK', msg[1].id, true, '']));
        console.log(`[${challenge}] ✅ Accepted event (authenticated)`);
        return;
      }

    } catch (e) {
      console.error(`[${challenge}] Error processing message:`, e);
    }
  });

  // Helper to handle the auth flow
  async function handleAuth(ws: WebSocket, msg: any, expectedChallenge: string) {
    const tokenObj = msg[1];
    console.log(`[${expectedChallenge}] Received AUTH token...`);

    // In a real NIP implementation, we'd parse the complex JSON object.
    // For this PoC, we expect the raw token struct from our SDK.
    
    try {
      // Use the SDK to verify the token against the Dockerized verifier
      // This checks: 1. Signature Validity 2. Expiration 3. Double-Spend
      const isValid = await freebird.verifyToken(tokenObj);

      if (isValid) {
        isAuthenticated = true;
        ws.send(JSON.stringify(['OK', 'auth', true, 'welcome freebird']));
        console.log(`[${expectedChallenge}] 🔓 Auth SUCCESS! Client is verified.`);
      } else {
        ws.send(JSON.stringify(['OK', 'auth', false, 'invalid token']));
        console.log(`[${expectedChallenge}] 🔒 Auth FAILED. Token rejected.`);
      }
    } catch (err) {
      console.error('Verification error:', err);
      ws.send(JSON.stringify(['OK', 'auth', false, 'error']));
    }
  }
});