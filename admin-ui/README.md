# Freebird Unified Admin Dashboard

A single-page web interface for managing both Freebird **issuer** and **verifier** services. The UI automatically detects which service it's connected to and shows the appropriate tabs and functionality.

## Features

### Unified Service Detection

The admin UI automatically detects whether it's running on an issuer or verifier by calling `/admin/health` and checking the `service` field in the response. Tabs and features are shown/hidden accordingly.

### Issuer Features

**Dashboard Tab:**
- Real-time system statistics (users, invitations, redemptions)
- Interactive activity charts with Canvas visualization
- Monitor banned users and system health

**User Management Tab:**
- Search and filter users
- View detailed user profiles with reputation scores
- Interactive invitation tree visualization
- Ban users individually or recursively (entire invite tree)

**Invitations Tab:**
- Create cryptographically signed invitation codes
- Grant invitation quota to users
- Track redemption status and expiration

**Key Management Tab:**
- View active and deprecated cryptographic keys
- Rotate keys with configurable grace periods
- Clean up expired keys

**Audit Logs Tab:**
- Comprehensive system activity logs
- Filter by level (info, warning, error, success)
- Search logs by keyword

**Federation Tab:**
- Manage federation relationships with other issuers
- View trusted peers and cross-issuer policies

**Sybil Configuration Tab:**
- View and modify Sybil resistance settings
- Configure invitation limits, cooldowns, and expiration
- Adjust proof-of-work difficulty and rate limits
- Monitor active Sybil resistance mechanism

**WebAuthn Tab:**
- Register FIDO2 credentials and security keys
- Manage biometric authentication
- Remove credentials

### Verifier Features

**Dashboard Tab:**
- Verification statistics and epoch information
- Uptime and store backend status
- Trusted issuer count

**Trusted Issuers Tab:**
- View all configured trusted issuers
- Inspect issuer details (public key, context, expiration)
- Trigger issuer metadata refresh

**Cache Tab:**
- Replay cache statistics
- Cache backend status
- Cache management operations

## Access

**Issuer Admin:**
```
http://localhost:8081/admin
```

**Verifier Admin:**
```
http://localhost:8082/admin
```

## Setup

1. **Set your Admin API Key** in the environment:
   ```bash
   export ADMIN_API_KEY="your-secure-key-at-least-32-characters"
   ```

2. **Enter the API key** in the dashboard's key field

3. **Click "Save & Test"** to verify the connection

4. The UI will detect the service type and show appropriate tabs

## Architecture

### Unified Codebase

The admin UI is a single HTML file that serves both services:

```
admin-ui/
└── index.html          # Source file (~3500 lines)

issuer/
├── build.rs            # Syncs index.html at compile time
└── src/admin_ui/
    └── index.html      # Synced copy (embedded in binary)

verifier/
├── build.rs            # Syncs index.html at compile time
└── src/admin_ui/
    └── index.html      # Synced copy (embedded in binary)
```

### Build Integration

Each service's `build.rs` copies the shared admin UI to its local directory:

```rust
// build.rs
fn main() {
    let src = Path::new("../admin-ui/index.html");
    let dst = Path::new("src/admin_ui/index.html");
    fs::copy(src, dst).ok();
    println!("cargo:rerun-if-changed=../admin-ui/index.html");
}
```

The HTML is then embedded at compile time:

```rust
// routes/admin.rs
pub async fn admin_ui_handler() -> impl IntoResponse {
    const ADMIN_UI_HTML: &str = include_str!("../admin_ui/index.html");
    Html(ADMIN_UI_HTML)
}
```

### Technology Stack

- **Single HTML file** with embedded CSS and JavaScript
- **No build step** - served directly from binary
- **No external dependencies** except water.css (CDN)
- **Vanilla JavaScript** with async/await
- **Canvas-based visualizations** for charts and trees
- **LocalStorage** for API key persistence
- **CSS custom properties** for theming

### Responsive Design

- Desktop-first with tablet and mobile breakpoints
- Collapsible navigation on small screens
- Touch-optimized controls
- Print-friendly styles
- Dark mode support via `prefers-color-scheme`
- Reduced motion support via `prefers-reduced-motion`

## Security

- API key stored in browser localStorage only
- All requests authenticated via `X-Admin-Key` header
- Rate limiting on authentication failures
- Constant-time key comparison to prevent timing attacks
- Always use HTTPS in production

## API Endpoints

### Shared (Both Services)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/admin/` | GET | Serve admin UI |
| `/admin/health` | GET | Health check with service type |
| `/admin/stats` | GET | System statistics |
| `/admin/config` | GET | Configuration values |
| `/admin/metrics` | GET | Prometheus metrics |

### Issuer-Only

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/admin/users` | GET | List all users |
| `/admin/users/:id` | GET | User details and invite tree |
| `/admin/users/ban` | POST | Ban user (optionally recursive) |
| `/admin/invitations/create` | POST | Create invitation codes |
| `/admin/invites/grant` | POST | Grant invitation quota |
| `/admin/invitations` | GET | List invitations |
| `/admin/invitations/:code` | GET | Get invitation details |
| `/admin/keys` | GET | List cryptographic keys |
| `/admin/keys/rotate` | POST | Rotate keys |
| `/admin/keys/cleanup` | POST | Remove expired keys |
| `/admin/audit` | GET | Retrieve audit logs |
| `/admin/sybil/config` | GET | Get Sybil configuration |
| `/admin/sybil/config` | PUT | Update Sybil configuration |
| `/admin/webauthn/register` | POST | Register credential |
| `/admin/webauthn/credentials` | GET | List credentials |
| `/admin/webauthn/credentials/remove` | POST | Remove credential |

### Verifier-Only

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/admin/issuers` | GET | List trusted issuers |
| `/admin/issuers/:id` | GET | Issuer details |
| `/admin/issuers/:id/refresh` | POST | Refresh issuer metadata |
| `/admin/cache/stats` | GET | Cache statistics |
| `/admin/cache/clear` | POST | Clear replay cache |

## Development

### Making Changes

1. Edit `admin-ui/index.html`
2. Rebuild either service:
   ```bash
   cargo build -p freebird-issuer
   # or
   cargo build -p freebird-verifier
   ```
3. The build.rs script will sync the changes
4. Restart the service

### Code Style

The code is formatted with Prettier and validated with html-validate:

```bash
# Format
prettier --write admin-ui/index.html

# Validate
npx html-validate admin-ui/index.html
```

### Adding New Tabs

1. Add tab button in the `.tabs` div with appropriate class:
   - `issuer-only` for issuer-specific tabs
   - `verifier-only hidden` for verifier-specific tabs
2. Add corresponding `tab-content` div
3. Add load function and API method
4. Update `detectServiceType()` if needed

## Browser Compatibility

- Chrome, Firefox, Safari, Edge (modern versions)
- JavaScript required
- Uses Fetch API, async/await, CSS Grid, Flexbox
- Canvas for charts and visualizations
