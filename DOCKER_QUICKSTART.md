# 🐳 Freebird Docker Quickstart Guide

This guide will help you get Freebird up and running with Docker in minutes.

## Prerequisites

- **Docker** (20.10 or later)
- **Docker Compose** (2.0 or later)
- **Git** (for cloning the repository)

Check your versions:
```bash
docker --version
docker compose version
```

## Quick Start (TL;DR)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/freebird.git
cd freebird

# 2. Create environment file
cp .env.example .env

# 3. Start all services
docker compose up --build

# 4. Test the deployment
curl http://localhost:8081/.well-known/issuer
```

That's it! Freebird is now running on your machine.

## Detailed Setup Guide

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/freebird.git
cd freebird
```

### Step 2: Configure Environment Variables

The `.env.example` file contains all available configuration options with sensible defaults for development.

```bash
# Copy the example configuration
cp .env.example .env

# (Optional) Edit the configuration
nano .env  # or vim, code, etc.
```

**Important variables for quickstart:**

| Variable | Default | Description |
|----------|---------|-------------|
| `ISSUER_ID` | `issuer:docker:v1` | Unique identifier for your issuer |
| `ADMIN_API_KEY` | `dev-admin-key...` | Admin API key (change in production!) |
| `SYBIL_RESISTANCE` | `invitation` | Sybil resistance mechanism |
| `SYBIL_INVITE_BOOTSTRAP_USERS` | `admin:100` | Bootstrap user with 100 invitations |
| `RUST_LOG` | `info,freebird=debug` | Log level |

**For development:** The defaults work out of the box—no changes needed!

**For production:** See the [Production Deployment](#production-deployment) section below.

### Step 3: Start the Services

```bash
# Start all services (issuer, verifier, redis)
docker compose up --build
```

This will:
1. Build the Freebird Docker images (~5-10 minutes on first build)
2. Start the Issuer (port 8081)
3. Start the Verifier (port 8082)
4. Start Redis (internal networking only)
5. Create persistent volumes for keys and state

**Tip:** Use `-d` flag to run in detached mode (background):
```bash
docker compose up --build -d
```

### Step 4: Verify the Deployment

Check that the services are healthy:

```bash
# Check service status
docker compose ps

# Fetch issuer metadata
curl http://localhost:8081/.well-known/issuer

# Check verifier health (should return issuer metadata)
curl http://localhost:8082/
```

**Expected output:**
```json
{
  "issuer_id": "issuer:docker:v1",
  "public_key": "...",
  "token_ttl_minutes": 10,
  "sybil_resistance": {
    "enabled": true,
    "mechanisms": ["invitation"]
  }
}
```

## Using Freebird

### Option 1: Using the TypeScript SDK

Install the SDK in your Node.js project:

```bash
npm install @freebird/sdk
```

```typescript
import { FreebirdClient } from '@freebird/sdk';

const client = new FreebirdClient({
  issuerUrl: 'http://localhost:8081',
  verifierUrl: 'http://localhost:8082'
});

// Initialize (fetch keys)
await client.init();

// Issue a token (requires invitation code if using invitation system)
const token = await client.issueToken({
  invitationCode: 'your-invitation-code'
});

// Verify the token
const isValid = await client.verifyToken(token);
console.log('Token valid:', isValid);
```

### Option 2: Using the Rust CLI Interface

The repository includes a CLI interface for testing:

```bash
# Build the CLI
docker compose exec issuer sh -c "cd /app && cargo build --release --bin interface"

# Run stress test (issues 5 tokens)
docker compose exec issuer /app/target/release/interface --stress 5
```

### Option 3: Using cURL (Manual Testing)

See the [API Examples](#api-examples) section below.

## API Examples

### 1. Issue a Token (with Invitation System)

First, create an invitation as the bootstrap admin user:

```bash
# Create an invitation
curl -X POST http://localhost:8081/api/admin/invitations \
  -H "X-Admin-API-Key: dev-admin-key-must-be-at-least-32-characters-long" \
  -H "Content-Type: application/json" \
  -d '{"inviter_id": "admin", "count": 1}'
```

**Response:**
```json
{
  "invitations": [
    "INV_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  ]
}
```

Now use the invitation code to issue a token:

```bash
# Get a token using the invitation
INVITE_CODE="INV_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

curl -X POST http://localhost:8081/token \
  -H "Content-Type: application/json" \
  -d "{\"invitation_code\": \"$INVITE_CODE\", \"user_id\": \"alice\"}"
```

### 2. Verify a Token

```bash
# Verify the token
curl -X POST http://localhost:8082/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_VALUE_HERE"}'
```

**Response:**
```json
{
  "valid": true,
  "issuer_id": "issuer:docker:v1",
  "expires_at": 1234567890
}
```

### 3. Admin API Examples

```bash
# View system statistics
curl http://localhost:8081/api/admin/stats \
  -H "X-Admin-API-Key: dev-admin-key-must-be-at-least-32-characters-long"

# Trigger manual key rotation
curl -X POST http://localhost:8081/api/admin/rotate-key \
  -H "X-Admin-API-Key: dev-admin-key-must-be-at-least-32-characters-long"

# List active keys
curl http://localhost:8081/api/admin/keys \
  -H "X-Admin-API-Key: dev-admin-key-must-be-at-least-32-characters-long"
```

## Common Operations

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f issuer
docker compose logs -f verifier
docker compose logs -f redis
```

### Restart Services

```bash
# Restart all services
docker compose restart

# Restart specific service
docker compose restart issuer
```

### Stop Services

```bash
# Stop all services (preserves data)
docker compose down

# Stop and remove volumes (deletes all data!)
docker compose down -v
```

### Update Configuration

1. Edit the `.env` file
2. Restart the services:
   ```bash
   docker compose down
   docker compose up -d
   ```

### Access Service Shell

```bash
# Access issuer container
docker compose exec issuer sh

# Access verifier container
docker compose exec verifier sh

# Access Redis CLI
docker compose exec redis redis-cli
```

## Troubleshooting

### Issue: Issuer not starting

**Check logs:**
```bash
docker compose logs issuer
```

**Common causes:**
- Invalid `ADMIN_API_KEY` (must be ≥32 characters)
- Port 8081 already in use
- Insufficient entropy (check: `cat /proc/sys/kernel/random/entropy_avail`)

**Solution:**
```bash
# Check port usage
lsof -i :8081

# Stop conflicting service or change port in .env
```

### Issue: Verifier can't reach Issuer

**Symptom:** Verifier logs show connection errors to issuer

**Solution:** Ensure services are on the same Docker network:
```bash
docker compose down
docker compose up --build
```

### Issue: Redis connection failed

**Check Redis status:**
```bash
docker compose ps redis
docker compose logs redis
```

**Solution:**
```bash
# Restart Redis
docker compose restart redis

# Or remove and recreate
docker compose down
docker compose up -d redis
```

### Issue: "Permission denied" errors

**Cause:** The Docker containers run as a non-root user (`freebird`)

**Solution:** Ensure volumes have correct permissions:
```bash
# This is usually automatic, but if issues persist:
docker compose down -v  # Remove volumes
docker compose up --build  # Recreate with correct permissions
```

### Issue: Build fails with dependency errors

**Solution:** Clear Docker build cache:
```bash
docker compose build --no-cache
```

## Production Deployment

⚠️ **IMPORTANT:** Do NOT use the default configuration in production!

### Essential Production Changes

1. **Security:**
   ```bash
   # Generate a secure admin API key
   ADMIN_API_KEY=$(openssl rand -base64 32)

   # Enable TLS
   REQUIRE_TLS=true
   BEHIND_PROXY=true
   ```

2. **Separate Infrastructure:**
   - Deploy Issuer and Verifier on **different servers/VPCs**
   - Use a reverse proxy (Nginx, Caddy, Traefik) for TLS termination
   - Update `ISSUER_URL` in verifier config to use public domain

3. **Persistent Storage:**
   - Use managed Redis (AWS ElastiCache, Redis Cloud, etc.)
   - Configure backups for Docker volumes
   - Use secrets manager for `ADMIN_API_KEY`

4. **Monitoring:**
   - Enable JSON logging: `LOG_FORMAT=json`
   - Set appropriate log levels: `RUST_LOG=info,freebird=info`
   - Set up health check monitoring for `/` and `/.well-known/issuer`

5. **Sybil Resistance:**
   - Change default salts:
     ```bash
     SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json
     SYBIL_PROGRESSIVE_TRUST_SALT=$(openssl rand -hex 32)
     SYBIL_PROOF_OF_DIVERSITY_SALT=$(openssl rand -hex 32)
     ```
   - Consider using `SYBIL_RESISTANCE=combined` for multiple mechanisms

### Example Production docker-compose.yml

See [`docs/production-docker-compose.yml`](docs/production-docker-compose.yml) for a production-ready configuration template.

## Next Steps

- **Integration:** Check out the [TypeScript SDK documentation](https://github.com/yourusername/freebird/tree/main/sdk/typescript)
- **Federation:** Learn about [Multi-Issuer Federation](docs/FEDERATION.md)
- **Advanced Sybil Resistance:** Explore [WebAuthn](docs/WEBAUTHN.md) and other mechanisms
- **HSM Support:** See [HSM Configuration Guide](.env.hsm.example)

## Additional Resources

- [Main README](README.md) - Project overview
- [API Documentation](docs/API.md) - Complete API reference
- [Configuration Reference](.env.example) - All environment variables
- [Security Model](README.md#security-model) - Guarantees and limitations
- [Contributing Guide](CONTRIBUTING.md) - How to contribute

## Need Help?

- **Documentation:** Check the `docs/` folder
- **Issues:** [GitHub Issues](https://github.com/yourusername/freebird/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/freebird/discussions)

---

🕊️ **Happy Freebirding!**

_Privacy without compromise. Authorization without identity._
