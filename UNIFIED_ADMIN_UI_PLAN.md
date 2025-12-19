# Unified Admin UI Architecture Plan

## Executive Summary

This plan outlines the architecture for a **unified admin UI** that serves both the Freebird Issuer and Verifier services. The goal is to provide a consistent, professional administrative experience while maintaining the project's philosophy of simplicity and zero-build-step deployment.

---

## Current State Analysis

### Issuer Admin UI
- **Location**: `/admin-ui/index.html` (2,700+ lines)
- **Architecture**: Single-file vanilla JavaScript with embedded CSS
- **Features**: 7 tabs (Dashboard, Users, Invitations, Keys, Audit, Federation, WebAuthn)
- **Styling**: Water.css (CDN) + custom CSS
- **Serving**: Embedded at compile-time via `include_str!()`

### Verifier Admin UI
- **Status**: None - API-only service
- **Current endpoints**: Only `/v1/verify` and `/v1/verify/batch`

### Key Issues with Current Issuer UI
1. Single 2,700-line file is difficult to maintain
2. No visibility into verifier status
3. Basic styling (functional but not polished)
4. No service health overview across deployment

---

## Proposed Architecture

### Design Philosophy
1. **Single-file approach preserved** - No build step required
2. **Service-aware UI** - Automatically detects issuer vs verifier
3. **Unified codebase** - One HTML file serves both services
4. **Progressive disclosure** - Show only relevant features per service
5. **Modern UX** - Improved styling while keeping Water.css foundation

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Unified Admin UI                            │
│                   (admin-ui/index.html)                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐    ┌─────────────────────────────────┐ │
│  │   Service Detector  │───→│  Dynamic Tab Rendering          │ │
│  │   GET /admin/health │    │  - Issuer: All 8 tabs           │ │
│  └─────────────────────┘    │  - Verifier: 4 tabs             │ │
│                              └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                         Tab Modules                              │
│  ┌──────────┬──────────┬──────────┬──────────┬────────────────┐ │
│  │Dashboard │ Issuers  │  Cache   │  Config  │    Metrics     │ │
│  │ (both)   │(verifier)│(verifier)│  (both)  │    (both)      │ │
│  ├──────────┼──────────┼──────────┼──────────┼────────────────┤ │
│  │  Users   │Invites   │   Keys   │  Audit   │   Federation   │ │
│  │(issuer)  │(issuer)  │ (issuer) │ (issuer) │    (issuer)    │ │
│  └──────────┴──────────┴──────────┴──────────┴────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
    ┌─────────────┐                      ┌─────────────┐
    │   Issuer    │                      │  Verifier   │
    │  :8081      │                      │   :8082     │
    │ /admin/*    │                      │  /admin/*   │
    └─────────────┘                      └─────────────┘
```

---

## Implementation Phases

### Phase 1: Verifier Admin API (Backend)

Add admin endpoints to the verifier service.

#### New Verifier Admin Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/` | GET | Serve admin UI HTML |
| `/admin/health` | GET | Service health + type identification |
| `/admin/stats` | GET | Verification statistics |
| `/admin/config` | GET | Current configuration |
| `/admin/issuers` | GET | List trusted issuers |
| `/admin/issuers/:id` | GET | Issuer details |
| `/admin/issuers/:id/refresh` | POST | Force metadata refresh |
| `/admin/cache/stats` | GET | Replay cache statistics |
| `/admin/cache/clear` | POST | Clear replay cache (dev only) |
| `/admin/metrics` | GET | Verification metrics |

#### Files to Create/Modify

```
verifier/src/
├── routes/
│   ├── mod.rs              # Add admin module
│   ├── admin.rs            # NEW: Admin routes (~400 lines)
│   └── admin_rate_limit.rs # NEW: Copy from issuer
├── admin_ui/
│   └── index.html          # Symlink or build.rs copy
└── main.rs                 # Mount admin router
```

#### Response Types

```rust
// GET /admin/health
pub struct HealthResponse {
    pub service: String,        // "verifier"
    pub status: String,         // "ok"
    pub uptime_seconds: u64,
    pub store_backend: String,  // "redis" or "memory"
    pub issuers_loaded: usize,
}

// GET /admin/stats
pub struct VerifierStatsResponse {
    pub total_verifications: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
    pub replay_detections: u64,
    pub current_epoch: u64,
    pub valid_epoch_range: (u64, u64),
    pub cache_size: Option<usize>,
    pub timestamp: u64,
}

// GET /admin/issuers
pub struct IssuerInfo {
    pub issuer_id: String,
    pub kid: String,
    pub pubkey_hash: String,  // First 8 chars of base64
    pub last_refreshed: u64,
    pub status: String,       // "fresh", "stale", "error"
}

// GET /admin/config
pub struct ConfigResponse {
    pub max_clock_skew_secs: u64,
    pub epoch_duration_sec: u64,
    pub epoch_retention: u64,
    pub refresh_interval_min: u64,
    pub store_backend: String,
    pub issuer_urls: Vec<String>,
    pub federation_enabled: bool,
}
```

---

### Phase 2: Unified Admin UI (Frontend)

Refactor the admin UI to support both services.

#### UI Structure

```
┌─────────────────────────────────────────────────────────────────┐
│  🕊️ Freebird Admin                    [Issuer ▾] [Disconnect]  │
├─────────────────────────────────────────────────────────────────┤
│  [Dashboard] [Users] [Invitations] [Keys] [Audit] [Federation] │
│                                                                 │
│  ═══════════════════════════════════════════════════════════   │
│                                                                 │
│   ISSUER MODE: All tabs visible                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  🕊️ Freebird Admin                   [Verifier ▾] [Disconnect] │
├─────────────────────────────────────────────────────────────────┤
│  [Dashboard] [Issuers] [Cache] [Metrics]                        │
│                                                                 │
│  ═══════════════════════════════════════════════════════════   │
│                                                                 │
│   VERIFIER MODE: Reduced tab set                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Service Detection Logic

```javascript
const CONFIG = {
    serviceType: null,  // 'issuer' or 'verifier'
    // ...existing config
};

async function detectService() {
    const response = await fetch('/admin/health', {
        headers: { 'X-Admin-Key': CONFIG.apiKey }
    });
    const data = await response.json();
    CONFIG.serviceType = data.service;  // 'issuer' or 'verifier'
    renderTabsForService();
}

function renderTabsForService() {
    const issuerOnlyTabs = ['users', 'invitations', 'keys', 'audit', 'federation', 'webauthn'];
    const verifierOnlyTabs = ['issuers', 'cache', 'metrics'];

    if (CONFIG.serviceType === 'verifier') {
        issuerOnlyTabs.forEach(tab => hideTab(tab));
        verifierOnlyTabs.forEach(tab => showTab(tab));
    } else {
        verifierOnlyTabs.forEach(tab => hideTab(tab));
        issuerOnlyTabs.forEach(tab => showTab(tab));
    }
}
```

#### Tab Configuration

| Tab | Service | Description |
|-----|---------|-------------|
| Dashboard | Both | Service health, stats, activity chart |
| Users | Issuer | User management, banning, invite trees |
| Invitations | Issuer | Create/list invitations, grant quota |
| Keys | Issuer | VOPRF key rotation and management |
| Audit | Issuer | Audit log viewer with filtering |
| Federation | Issuer | Vouches and revocations |
| WebAuthn | Issuer | Credential management (if enabled) |
| Issuers | Verifier | Trusted issuer management |
| Cache | Verifier | Replay cache stats and management |
| Metrics | Verifier | Verification performance metrics |

---

### Phase 3: Build Integration

#### Option A: Build Script (Recommended)

Create `build.rs` in both services to sync the admin UI:

```rust
// issuer/build.rs and verifier/build.rs
use std::fs;
use std::path::Path;

fn main() {
    let src = Path::new("../admin-ui/index.html");
    let dst = Path::new("src/admin_ui/index.html");

    // Create directory if needed
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).ok();
    }

    // Copy file
    if src.exists() {
        fs::copy(src, dst).expect("Failed to copy admin UI");
        println!("cargo:rerun-if-changed=../admin-ui/index.html");
    }
}
```

#### Option B: Symlinks

```bash
# One-time setup
ln -sf ../../admin-ui/index.html issuer/src/admin_ui/index.html
ln -sf ../../admin-ui/index.html verifier/src/admin_ui/index.html
```

---

### Phase 4: Enhanced UX Improvements

#### 4.1 Visual Improvements

```css
/* Enhanced color palette */
:root {
    --primary: #0076d1;
    --primary-dark: #005ba1;
    --success: #10b981;
    --warning: #f59e0b;
    --error: #ef4444;
    --surface: #f8fafc;
    --surface-alt: #f1f5f9;
    --text: #1e293b;
    --text-muted: #64748b;
    --border: #e2e8f0;
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
}

/* Service indicator badge */
.service-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.service-badge.issuer {
    background: #dbeafe;
    color: #1d4ed8;
}

.service-badge.verifier {
    background: #d1fae5;
    color: #059669;
}
```

#### 4.2 Dashboard Enhancements

**Issuer Dashboard:**
- User growth chart (existing)
- Invitation redemption rate
- Active keys indicator
- Recent audit events

**Verifier Dashboard (New):**
- Verification throughput chart
- Success/failure ratio pie chart
- Issuer health status grid
- Cache utilization meter
- Current epoch display

#### 4.3 Responsive Design

```css
/* Mobile-first improvements */
@media (max-width: 768px) {
    .tabs {
        flex-wrap: nowrap;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }

    .form-row {
        flex-direction: column;
    }
}
```

---

## File Structure After Implementation

```
freebird/
├── admin-ui/
│   ├── index.html           # Unified admin UI (~3,500 lines)
│   └── README.md            # Documentation
│
├── issuer/
│   ├── build.rs             # Copies admin-ui/index.html
│   ├── Cargo.toml
│   └── src/
│       ├── admin_ui/
│       │   └── index.html   # Auto-copied by build.rs
│       ├── routes/
│       │   ├── admin.rs     # Updated health endpoint
│       │   └── ...
│       └── ...
│
├── verifier/
│   ├── build.rs             # NEW: Copies admin-ui/index.html
│   ├── Cargo.toml           # Add admin feature flag
│   └── src/
│       ├── admin_ui/
│       │   └── index.html   # NEW: Auto-copied by build.rs
│       ├── routes/
│       │   ├── mod.rs       # NEW: Add admin module
│       │   ├── admin.rs     # NEW: Admin routes
│       │   └── admin_rate_limit.rs  # NEW: Rate limiting
│       └── main.rs          # Mount admin router
│
└── docker-compose.yml       # Add ADMIN_API_KEY for verifier
```

---

## API Compatibility

### Issuer Health Response (Updated)

```json
{
    "service": "issuer",
    "status": "ok",
    "uptime_seconds": 3600,
    "invitation_system_status": "operational"
}
```

### Verifier Health Response (New)

```json
{
    "service": "verifier",
    "status": "ok",
    "uptime_seconds": 3600,
    "store_backend": "redis",
    "issuers_loaded": 3
}
```

---

## Security Considerations

1. **Shared authentication**: Both services use `X-Admin-Key` header
2. **Rate limiting**: Copy issuer's rate limiting to verifier
3. **Audit logging**: Add audit trail to verifier admin actions
4. **Feature flags**: Make verifier admin optional via feature flag
5. **Clear cache protection**: Require confirmation for destructive actions

---

## Environment Variables

### Issuer (Existing)
```bash
ADMIN_API_KEY=<min 32 chars>
BEHIND_PROXY=true  # For X-Forwarded-For
```

### Verifier (New)
```bash
ADMIN_API_KEY=<min 32 chars>      # NEW
BEHIND_PROXY=true                  # NEW
ADMIN_ENABLED=true                 # NEW: Optional, default true
```

---

## Docker Compose Updates

```yaml
services:
  issuer:
    environment:
      - ADMIN_API_KEY=${ADMIN_API_KEY}
    ports:
      - "8081:8081"

  verifier:
    environment:
      - ADMIN_API_KEY=${ADMIN_API_KEY}    # NEW
      - ADMIN_ENABLED=true                 # NEW
    ports:
      - "8082:8082"
```

---

## Implementation Checklist

### Phase 1: Verifier Backend
- [ ] Create `verifier/src/routes/admin.rs`
- [ ] Create `verifier/src/routes/admin_rate_limit.rs`
- [ ] Add admin router to `verifier/src/main.rs`
- [ ] Implement `/admin/health` with service type
- [ ] Implement `/admin/stats` for verification metrics
- [ ] Implement `/admin/config` for configuration view
- [ ] Implement `/admin/issuers` for issuer management
- [ ] Implement `/admin/cache/stats` for cache info
- [ ] Implement `/admin/cache/clear` for cache reset
- [ ] Add `ADMIN_API_KEY` environment variable support
- [ ] Add rate limiting middleware

### Phase 2: Unified Frontend
- [ ] Update issuer `/admin/health` to include `service: "issuer"`
- [ ] Add service detection to admin UI
- [ ] Create verifier-specific tabs (Issuers, Cache, Metrics)
- [ ] Implement conditional tab rendering
- [ ] Add service indicator badge in header
- [ ] Update dashboard for dual-service support

### Phase 3: Build Integration
- [ ] Create `issuer/build.rs` for UI sync
- [ ] Create `verifier/build.rs` for UI sync
- [ ] Create `verifier/src/admin_ui/` directory
- [ ] Update `.gitignore` for generated files
- [ ] Test build process

### Phase 4: Polish
- [ ] Improve CSS styling
- [ ] Add responsive design improvements
- [ ] Add loading states
- [ ] Add error handling improvements
- [ ] Update documentation
- [ ] Update docker-compose.yml

---

## Success Metrics

1. **Single codebase**: One `index.html` serves both services
2. **Zero build step**: No npm/node required
3. **Service awareness**: UI adapts to connected service
4. **Feature parity**: Verifier has comparable admin experience
5. **Maintainability**: Clear separation of concerns in code

---

## Future Considerations

1. **Multi-service dashboard**: Connect to both issuer AND verifier simultaneously
2. **Metrics aggregation**: Combine stats from multiple services
3. **Alert integration**: Webhook notifications for critical events
4. **Dark mode**: User preference for light/dark theme
5. **Internationalization**: Multi-language support

---

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: Verifier Backend | ~400 lines Rust | None |
| Phase 2: Unified Frontend | ~800 lines JS/HTML | Phase 1 |
| Phase 3: Build Integration | ~50 lines Rust | Phase 2 |
| Phase 4: Polish | ~200 lines CSS | Phase 2 |

**Total estimated new code**: ~1,450 lines

---

## Conclusion

This plan provides a pragmatic path to a unified admin UI that:
- Maintains the project's simplicity philosophy
- Requires no new build dependencies
- Provides full visibility into both services
- Improves the overall administrative experience

The phased approach allows incremental delivery while ensuring each phase provides standalone value.
