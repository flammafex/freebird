# Freebird Admin Dashboard

A minimal, single-page web interface for managing your Freebird deployment.

## Features

### Phase 1 (Current)

**📊 Dashboard Tab:**
- View system statistics
- Monitor user counts, invitations, and redemptions
- Check banned user statistics
- Real-time refresh

**🎫 Invitations Tab:**
- Create invitation codes with cryptographic signatures
- Grant invitation quota to users
- Copy codes and signatures to clipboard
- View expiration dates

### Future Phases

- **Phase 2:** User management (view users, ban users, view invite trees)
- **Phase 3:** Key management & system monitoring
- **Phase 4:** Advanced features (invitation tree visualization, token testing, real-time charts)

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

- **Single HTML file** (~700 lines) with embedded CSS and JavaScript
- **No build step** required - served directly from the issuer
- **No external dependencies** except water.css (CDN)
- **Tab-based navigation** ready for Phase 2 expansion
- **Modular JavaScript** with clean API client architecture
- **LocalStorage** for API key persistence

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
| `/admin/invitations/create` | POST | Generate invitation codes |
| `/admin/invites/grant` | POST | Grant invitation quota to users |

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
