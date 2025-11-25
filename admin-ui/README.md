# Freebird Admin Dashboard

A minimal, single-page web interface for managing your Freebird deployment.

## Features

### Current Features (Phases 1-4 Complete)

**📊 Dashboard Tab:**
- View real-time system statistics
- Monitor user counts, invitations, and redemptions
- Check banned user statistics and system health
- One-click refresh
- **NEW:** Real-time activity charts with interactive visualization
- **NEW:** Track user growth, invitations, and redemptions over time

**👥 User Management Tab:**
- View all users with search and filtering
- Inspect detailed user profiles with reputation scores
- View invitation trees and relationships
- **NEW:** Interactive invitation tree visualization with Canvas graphics
- Ban individual users or entire invitation trees (recursive bans)
- Monitor user activity and invitation usage

**🎫 Invitations Tab:**
- Create cryptographically signed invitation codes
- Grant invitation quota to users
- View invitation history with redemption status
- Copy codes and signatures to clipboard
- Monitor expiration dates and usage

**🔑 Key Management Tab:**
- View active and deprecated cryptographic keys
- Rotate keys with configurable grace periods
- Clean up expired keys
- Monitor key status, public keys, and expiration times

**🎟️ Token Testing Tab (NEW):**
- Issue test VOPRF tokens for any user ID
- Verify token signatures inline
- Copy tokens and signatures to clipboard
- Auto-fill verification form after issuance
- View token expiration and validation details

**📝 Audit Logs Tab (NEW):**
- View comprehensive system activity logs
- Search and filter logs by keyword
- Filter by log level (info, warning, error, success)
- Track user actions and system events
- Real-time log refresh

**🔐 WebAuthn Management Tab (NEW):**
- View all registered WebAuthn credentials ✅
- Search credentials by user ID ✅
- Monitor credential usage and creation dates ✅
- Remove credentials with one click ✅
- ⚠️ **Note:** Credential registration must be done through the user-facing `/webauthn` endpoints (requires browser WebAuthn API)

## Access

Once your Freebird issuer is running:

```
http://localhost:8081/admin
```

## Setup

1. **Enter your Admin API Key** from your `.env` file
   - Default: `dev-admin-key-must-be-at-least-32-characters-long`
   - Production: Use a secure 32+ character key

2. **Click "Save & Test"** to verify the connection

3. **Start managing!**

## Architecture

- **Single HTML file** (~2100 lines) with embedded CSS and JavaScript
- **No build step** required - served directly from the issuer binary
- **No external dependencies** except water.css (CDN)
- **Seven-tab interface** with smooth navigation and state management
- **Modular JavaScript** with clean API client architecture
- **Canvas-based visualizations** for charts and tree graphs
- **LocalStorage** for API key persistence
- **Responsive design** works on desktop and mobile browsers

## Security

- API key stored in browser's localStorage only
- All API requests use the `X-Admin-Key` header
- No sensitive data transmitted except via API calls
- Always use HTTPS in production

## API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/admin/health` | GET | Verify API key and system health |
| `/admin/stats` | GET | Fetch system statistics |
| `/admin/users` | GET | List all users with their status |
| `/admin/users/:id` | GET | Get detailed user information and invite tree |
| `/admin/users/ban` | POST | Ban a user (optionally with entire invite tree) |
| `/admin/invitations/create` | POST | Generate invitation codes |
| `/admin/invites/grant` | POST | Grant invitation quota to users |
| `/admin/invitations` | GET | List invitation history with status |
| `/admin/keys` | GET | List all cryptographic keys |
| `/admin/keys/rotate` | POST | Rotate to a new key with grace period |
| `/admin/keys/cleanup` | POST | Remove expired keys |
| `/admin/tokens/issue` | POST | Issue a test VOPRF token for a user ⚠️ *Not yet implemented* |
| `/admin/tokens/verify` | POST | Verify a token signature ⚠️ *Not yet implemented* |
| `/admin/audit` | GET | Retrieve audit logs with filtering ⚠️ *Not yet implemented* |
| `/admin/webauthn/register` | POST | Register a new WebAuthn credential ⚠️ *Not implemented* (use user-facing `/webauthn` endpoints) |
| `/admin/webauthn/credentials` | GET | List all WebAuthn credentials ✅ *Implemented* |
| `/admin/webauthn/credentials/remove` | POST | Remove a WebAuthn credential ✅ *Implemented* |

## Development

The HTML is embedded in the Rust binary at compile time using `include_str!()`:

```rust
// issuer/src/routes/admin.rs
pub async fn admin_ui_handler() -> impl IntoResponse {
    const ADMIN_UI_HTML: &str = include_str!("../../../admin-ui/index.html");
    Html(ADMIN_UI_HTML)
}
```

To modify the dashboard:
1. Edit `admin-ui/index.html`
2. Rebuild the issuer: `cargo build --release --bin issuer`
3. Restart the issuer

## Browser Compatibility

- Modern browsers (Chrome, Firefox, Safari, Edge)
- Requires JavaScript enabled
- Uses Fetch API and async/await
- CSS Grid and Flexbox

## Contributing

When adding new features:
- Keep the single-file architecture
- Use vanilla JavaScript (no frameworks)
- Follow the existing tab-based structure
- Update the `CONFIG` object for new settings
- Add corresponding API methods to `FreebirdAdminAPI` class
