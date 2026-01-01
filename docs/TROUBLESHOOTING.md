# 🔧 Troubleshooting Guide

Common issues and solutions for Freebird deployment.

---

## Quick Diagnostics

### Is Everything Running?

```bash
# Check issuer
curl http://localhost:8081/.well-known/issuer

# Check verifier (implicit health check via test)
curl -X POST http://localhost:8082/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"token_b64": "test", "issuer_id": "test", "exp": 1}'

# Check Redis (if used)
redis-cli ping
# Should return: PONG
```

### Check Logs

```bash
# Issuer logs
journalctl -u freebird-issuer -n 100

# Verifier logs
journalctl -u freebird-verifier -n 100

# Follow logs in real-time
journalctl -u freebird-issuer -f
```

---

## Issuer Issues

### "Address already in use"

**Symptom:**
```
Error: Address already in use (os error 98)
```

**Cause:** Port 8081 is occupied by another process.

**Solution:**
```bash
# Find process using port
lsof -i :8081
sudo netstat -tulpn | grep :8081

# Kill process or use different port
export BIND_ADDR=127.0.0.1:9081
./target/release/issuer
```

---

### "Failed to load issuer key"

**Symptom:**
```
Error: failed to load issuer key from issuer_sk.bin
```

**Causes:**
1. File doesn't exist
2. Wrong file format
3. Permission denied
4. Corrupted file

**Solutions:**
```bash
# Check if file exists
ls -la issuer_sk.bin

# Check permissions
chmod 600 issuer_sk.bin

# Verify file format
file issuer_sk.bin
# Should be: data (32 bytes) or DER-encoded PKCS#8

# Regenerate if corrupted
rm issuer_sk.bin
./target/release/issuer
# Will generate new key
```

---

### "Admin API disabled"

**Symptom:**
```
⚠️ ADMIN_API_KEY is too short (< 32 chars), admin API disabled
```

**Cause:** `ADMIN_API_KEY` not set or too short.

**Solution:**
```bash
# Generate secure key
export ADMIN_API_KEY=$(openssl rand -base64 48)

# Persist in environment file
echo "ADMIN_API_KEY=$ADMIN_API_KEY" >> /etc/freebird/issuer.env

# Restart issuer
systemctl restart freebird-issuer
```

---

### "Sybil resistance proof required"

**Symptom:**
```
HTTP 400: Sybil resistance proof required
```

**Cause:** Issuer has Sybil resistance enabled but client didn't provide proof.

**Solutions:**
```bash
# Option 1: Disable Sybil resistance (development only)
export SYBIL_RESISTANCE=none
./target/release/issuer

# Option 2: Provide valid Sybil proof
# See invitation system or other Sybil mechanism documentation
```

---

### "Invitation not found"

**Symptom:**
```
HTTP 403: Sybil resistance verification failed: invitation not found
```

**Causes:**
1. Wrong invitation code (typo)
2. Invitation already expired and cleaned up
3. State file not loaded

**Solutions:**
```bash
# Check invitation exists
curl http://localhost:8081/admin/invitations/CODE \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Check state file loaded
curl http://localhost:8081/admin/stats \
  -H "X-Admin-Key: ${ADMIN_KEY}"

# Check issuer logs for state loading
journalctl -u freebird-issuer | grep "invitation"

# Verify state file is valid JSON
jq . invitations.json
```

---

### "Failed to save invitation state"

**Symptom:**
```
Error: failed to save invitation state: Permission denied
```

**Cause:** No write permission to state file location.

**Solution:**
```bash
# Check directory permissions
ls -la /var/lib/freebird/

# Fix permissions
sudo chown -R freebird:freebird /var/lib/freebird/
sudo chmod 755 /var/lib/freebird/
sudo chmod 600 /var/lib/freebird/invitations.json

# Restart issuer
systemctl restart freebird-issuer
```

---

## Verifier Issues

### "Failed to load issuer metadata"

**Symptom:**
```
Error: failed to fetch issuer metadata from http://localhost:8081/.well-known/issuer
```

**Causes:**
1. Issuer not running
2. Wrong ISSUER_URL
3. Network connectivity issue
4. TLS certificate error (if using HTTPS)

**Solutions:**
```bash
# Check issuer is running
curl http://localhost:8081/.well-known/issuer

# Verify ISSUER_URL is correct
echo $ISSUER_URL

# Test connectivity
telnet localhost 8081

# If using HTTPS, verify TLS
curl -v https://issuer.example.com/.well-known/issuer

# Check verifier logs
journalctl -u freebird-verifier | grep "metadata"
```

---

### "Failed to connect to Redis"

**Symptom:**
```
Error: failed to connect to Redis: Connection refused
```

**Causes:**
1. Redis not running
2. Wrong REDIS_URL
3. Redis authentication required

**Solutions:**
```bash
# Check Redis is running
systemctl status redis
redis-cli ping

# Test connection
redis-cli -h localhost -p 6379 ping

# Verify REDIS_URL
echo $REDIS_URL

# Check Redis auth (if configured)
redis-cli -h localhost -p 6379 -a PASSWORD ping

# Update REDIS_URL with auth
export REDIS_URL=redis://:PASSWORD@localhost:6379
```

---

### "Verification failed" (Token Already Used)

**Symptom:**
```
HTTP 401: {"ok": false, "error": "verification failed"}
```

**Cause:** Token was already verified (replay protection).

**Expected Behavior:** Tokens are single-use by design.

**Solutions:**
```bash
# Request new token from issuer
# This is not a bug - it's replay protection working correctly

# To test: Use interface tool
./target/release/interface --replay
# Should show: "REPLAY PROTECTION WORKING!"
```

---

### "Verification failed" (Token Expired)

**Symptom:**
```
HTTP 401: {"ok": false, "error": "verification failed"}
```

**Cause:** Token has expired.

**Check Expiration:**
```bash
# Current time
date +%s

# Token expiration (from issue response)
echo $TOKEN_EXP

# If current_time > exp + MAX_CLOCK_SKEW_SECS, token is expired
```

**Solutions:**
```bash
# Option 1: Request new token
./target/release/interface

# Option 2: Increase token TTL (issuer side)
export TOKEN_TTL_MIN=60  # 1 hour
systemctl restart freebird-issuer

# Option 3: Increase clock skew tolerance (verifier side)
export MAX_CLOCK_SKEW_SECS=600  # 10 minutes
systemctl restart freebird-verifier
```

---

## Clock Synchronization Issues

### "Token expired immediately"

**Symptom:** Token expires immediately after issuance.

**Cause:** Clock skew between issuer and verifier.

**Diagnosis:**
```bash
# Check issuer time
ssh issuer-host "date"

# Check verifier time
ssh verifier-host "date"

# Check NTP status
timedatectl status
ntpdate -q pool.ntp.org
```

**Solutions:**
```bash
# Synchronize clocks with NTP
sudo timedatectl set-ntp true

# Manual sync
sudo ntpdate pool.ntp.org

# Increase clock skew tolerance (temporary)
export MAX_CLOCK_SKEW_SECS=600
systemctl restart freebird-verifier

# Configure NTP permanently
# /etc/systemd/timesyncd.conf
[Time]
NTP=pool.ntp.org time.nist.gov

sudo systemctl restart systemd-timesyncd
```

---

## Performance Issues

### "Slow token issuance"

**Symptom:** Issuing tokens takes > 1 second.

**Diagnosis:**
```bash
# Benchmark with stress test
time ./target/release/interface --stress 100

# Check CPU usage
top -p $(pgrep issuer)

# Check Sybil resistance overhead
journalctl -u freebird-issuer | grep "Sybil"
```

**Solutions:**
```bash
# Option 1: Reduce Sybil resistance cost
export SYBIL_POW_DIFFICULTY=16  # Reduce from 20+

# Option 2: Increase CPU allocation
# Modify systemd service to use more cores

# Option 3: Use batch issuance
curl -X POST http://localhost:8081/v1/oprf/issue/batch \
  -d '{"blinded_elements": [...]}'
```

---

### "Slow verification"

**Symptom:** Verifying tokens takes > 100ms.

**Diagnosis:**
```bash
# Check Redis latency
redis-cli --latency

# Check nullifier database size
redis-cli DBSIZE

# Check verifier CPU
top -p $(pgrep verifier)
```

**Solutions:**
```bash
# Option 1: Clean up expired nullifiers
# Automatic cleanup should handle this

# Option 2: Optimize Redis
# /etc/redis/redis.conf
maxmemory-policy allkeys-lru
save ""  # Disable persistence for faster writes

# Option 3: Use Redis cluster (if very large scale)
```

---

## Network Issues

### "Connection refused"

**Symptom:** Can't connect to issuer/verifier.

**Causes:**
1. Service not running
2. Firewall blocking
3. Wrong IP/port
4. Binding to localhost instead of 0.0.0.0

**Solutions:**
```bash
# Check service is running
systemctl status freebird-issuer
ps aux | grep issuer

# Check binding address
netstat -tulpn | grep 8081

# Check firewall
sudo iptables -L -n
sudo firewall-cmd --list-all

# Allow port through firewall
sudo firewall-cmd --add-port=8081/tcp --permanent
sudo firewall-cmd --reload

# Bind to all interfaces
export BIND_ADDR=0.0.0.0:8081
systemctl restart freebird-issuer
```

---

### "TLS handshake failed"

**Symptom:**
```
Error: TLS handshake failed
```

**Causes:**
1. Self-signed certificate
2. Certificate expired
3. Hostname mismatch
4. Weak cipher suites

**Solutions:**
```bash
# Check certificate
openssl s_client -connect issuer.example.com:443 -showcerts

# Verify certificate validity
echo | openssl s_client -connect issuer.example.com:443 2>/dev/null | \
  openssl x509 -noout -dates

# Check hostname
echo | openssl s_client -connect issuer.example.com:443 2>/dev/null | \
  openssl x509 -noout -text | grep DNS

# Renew Let's Encrypt certificate
certbot renew
systemctl reload nginx
```

---

## Data Corruption

### "Invalid JSON in state file"

**Symptom:**
```
Error: failed to parse invitation state: invalid JSON
```

**Cause:** State file corrupted (disk failure, unclean shutdown, etc.).

**Solutions:**
```bash
# Validate JSON
jq . invitations.json

# Check for backup
ls -la /var/backups/freebird/

# Restore from backup
cp /var/backups/freebird/invitations_20241115.json invitations.json

# If no backup, reset state (WARNING: loses all invitation data)
rm invitations.json
systemctl restart freebird-issuer
# Will create new empty state

# Restore bootstrap users
curl -X POST http://localhost:8081/admin/bootstrap/add \
  -H "X-Admin-Key: ${ADMIN_KEY}" \
  -d '{"user_id": "admin", "invite_count": 100}'
```

---

## Common Configuration Mistakes

### Mismatched ISSUER_ID

**Symptom:** Verifier rejects all tokens.

**Cause:** Token's issuer_id doesn't match verifier's expected issuer_id.

**Solution:**
```bash
# Check issuer_id from metadata
curl http://localhost:8081/.well-known/issuer | jq '.issuer_id'

# Update verifier to use correct issuer
export ISSUER_URL=http://correct-issuer:8081/.well-known/issuer
systemctl restart freebird-verifier
```

---

### Wrong Token TTL

**Symptom:** Tokens expire too quickly or last too long.

**Solution:**
```bash
# Check current TTL
curl http://localhost:8081/.well-known/issuer | jq '.voprf.exp_sec'

# Update TTL
export TOKEN_TTL_MIN=60  # 1 hour
systemctl restart freebird-issuer
```

---

## Getting More Help

### Enable Debug Logging

```bash
# Issuer
export RUST_LOG=debug,freebird=trace
systemctl restart freebird-issuer

# Verifier
export RUST_LOG=debug,freebird=trace
systemctl restart freebird-verifier

# View detailed logs
journalctl -u freebird-issuer -f
```

### Collect Diagnostic Information

```bash
#!/bin/bash
# collect-diagnostics.sh

echo "=== System Info ===" > diagnostics.txt
uname -a >> diagnostics.txt
date >> diagnostics.txt

echo -e "\n=== Service Status ===" >> diagnostics.txt
systemctl status freebird-issuer >> diagnostics.txt
systemctl status freebird-verifier >> diagnostics.txt

echo -e "\n=== Recent Logs ===" >> diagnostics.txt
journalctl -u freebird-issuer -n 100 >> diagnostics.txt
journalctl -u freebird-verifier -n 100 >> diagnostics.txt

echo -e "\n=== Configuration ===" >> diagnostics.txt
cat /etc/freebird/issuer.env >> diagnostics.txt
cat /etc/freebird/verifier.env >> diagnostics.txt

echo -e "\n=== Network ===" >> diagnostics.txt
netstat -tulpn | grep -E "8081|8082" >> diagnostics.txt

echo "Diagnostics saved to diagnostics.txt"
```

### Report an Issue

When reporting issues, include:

1. **Symptom:** What's happening?
2. **Expected:** What should happen?
3. **Environment:** OS, Rust version, Freebird version
4. **Configuration:** Relevant environment variables (redact secrets!)
5. **Logs:** Recent logs showing the error
6. **Steps to reproduce:** How to trigger the issue

**GitHub Issues:** https://github.com/yourusername/freebird/issues

---

## Related Documentation

- [Configuration](CONFIGURATION.md) - Environment variables
- [Production Guide](PRODUCTION.md) - Deployment best practices
- [Security Model](SECURITY.md) - Expected behavior and limitations
- [API Reference](API.md) - Complete HTTP API documentation

---

**Still stuck? Open a GitHub issue with diagnostic information.**