import WebSocket from 'ws';
import { FreebirdClient } from '../src/index';

const RELAY_URL = 'ws://localhost:8080';
const ISSUER_URL = 'http://127.0.0.1:8081';

async function run() {
  // 1. Initialize SDK
  const client = new FreebirdClient({ issuerUrl: ISSUER_URL });
  await client.init();
  console.log('✅ SDK Initialized');

  // 2. Connect to Relay
  const ws = new WebSocket(RELAY_URL);

  ws.on('open', () => {
    console.log('🔗 Connected to Relay');
  });

  ws.on('message', async (data) => {
    const msg = JSON.parse(data.toString());
    console.log('📨 Relay says:', msg);

    // 3. Handle Auth Challenge
    if (msg[0] === 'AUTH' && msg[1].startsWith('freebird:v1')) {
      console.log('⚡ Received Freebird Challenge. Issuing token...');
      
      // ISSUE TOKEN anonymously
      const token = await client.issueToken();
      console.log('🎟️  Token obtained. Sending to relay...');

      // Reply with token
      ws.send(JSON.stringify(['AUTH', token]));

      // Try to publish an event immediately (will fail if auth is slow/broken)
      setTimeout(() => {
        const event = {
          id: 'test-event-id-' + Date.now(),
          kind: 1,
          content: 'Hello from Freebird!'
        };
        console.log('📝 Publishing event...');
        ws.send(JSON.stringify(['EVENT', event]));
      }, 1000);
    }
  });
}

run();