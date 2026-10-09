# ACME Automatic Certificate Management

This document describes Zentinel's ACME (Automatic Certificate Management Environment) implementation for automatic TLS certificate issuance and renewal via Let's Encrypt.

## Overview

Zentinel supports automatic TLS certificate management using the ACME protocol (RFC 8555). This eliminates the need for manual certificate management by automatically:

- Requesting certificates from Let's Encrypt
- Completing HTTP-01 or DNS-01 domain validation challenges
- **Wildcard certificate support** via DNS-01 challenges
- Storing certificates securely on disk
- Renewing certificates before expiration
- Hot-reloading certificates without proxy restart

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ACME Certificate Flow                         │
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │  AcmeClient  │────▶│ Let's Encrypt│────▶│   Storage    │        │
│  │              │     │    Server    │     │              │        │
│  │ - Account    │     │              │     │ - Certs      │        │
│  │ - Orders     │◀────│ - Challenges │     │ - Keys       │        │
│  │ - CSR        │     │ - Validation │     │ - Metadata   │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│         │                    │                    │                 │
│         ▼                    ▼                    ▼                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Challenge Handling                         │  │
│  │                                                               │  │
│  │  HTTP-01: Served from /.well-known/acme-challenge/            │  │
│  │  DNS-01:  TXT records via DNS provider API                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   RenewalScheduler                            │  │
│  │                                                               │  │
│  │  Event-driven deadline loop (ARI refresh & renewal deadlines) │  │
│  │  RFC 9773 ARI renewal windows with renew_before_days fallback │  │
│  │  Supports both HTTP-01 and DNS-01 renewal with replaces       │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Module Structure

### `acme/mod.rs`

Module exports and public API:

```rust
pub use ari::{AriCapability, AriError, AriErrorClassification, RenewalWindow};
pub use challenge::ChallengeManager;
pub use client::AcmeClient;
pub use error::AcmeError;
pub use scheduler::RenewalScheduler;
pub use storage::CertificateStorage;

// ARI and DNS-01 challenge support
pub mod ari;
pub mod dns;
```

### `acme/ari.rs` - RFC 9773 ACME Renewal Information (ARI)

Implements RFC 9773 ACME Renewal Information (ARI) support for CA-guided certificate renewal and predecessor replacement:

- **Certificate Identification**: Extracts RFC 9773 unique certificate identifiers (`{authorityKeyIdentifier}.{serialNumber}`) from leaf certificates.
- **Renewal Window Scheduling**: Validates CA-provided suggested renewal windows (`suggestedWindow`), uniformly selects a renewal time within the window, and keeps the selected time stable across refreshes unless the window changes.
- **Refresh Lifecycle**: Polls the CA for renewal info according to the server's `Retry-After` hint (clamped between 1 minute and 24 hours per RFC 9773 §4.3.2).
- **Error Recovery & Backoff**: Follows RFC 9773 §4.3.3 with bounded exponential backoff for temporary failures and ~6-hour retry intervals for long-term errors.
- **Capability Detection & Fallback**: Distinguishes supported, unsupported, and unknown/transient ARI states. When ARI is explicitly unsupported or unavailable, automatically falls back to the configured `renew-before-days` policy.
- **Order Linking (`replaces`)**: Automatically associates renewal orders with their predecessor certificates via `NewOrder::replaces()` when ARI support is confirmed.

### `acme/dns/` - DNS-01 Challenge Support

The DNS module provides DNS-01 challenge support for wildcard certificates:

```
acme/dns/
├── mod.rs           # Module exports
├── provider.rs      # DnsProvider trait and errors
├── challenge.rs     # Dns01ChallengeManager
├── propagation.rs   # DNS propagation checking
├── credentials.rs   # Secure credential loading
└── providers/
    ├── mod.rs       # Provider factory
    ├── hetzner.rs   # Hetzner DNS provider
    ├── cloudflare.rs # Cloudflare DNS provider
    └── webhook.rs   # Generic webhook provider
```

#### DNS Provider Trait

```rust
#[async_trait]
pub trait DnsProvider: Send + Sync + Debug {
    fn name(&self) -> &'static str;

    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> DnsResult<String>;  // Returns record ID

    async fn delete_txt_record(
        &self,
        domain: &str,
        record_id: &str,
    ) -> DnsResult<()>;

    async fn supports_domain(&self, domain: &str) -> DnsResult<bool>;
}
```
#### Supported DNS Providers

| Provider | Description |
|----------|-------------|
| `hetzner` | Hetzner DNS API |
| `cloudflare` | Cloudflare DNS API v4 |
| `webhook` | Generic webhook for custom DNS integrations |

#### DNS-01 Challenge Flow
...
### Custom ACME Directory and EAB

Zentinel supports custom ACME directory URLs and External Account Binding (EAB), which is required by providers like ZeroSSL.

```kdl
acme {
    email "admin@example.com"
    domains "example.com"

    // Custom ACME directory URL
    server-url "https://acme.zerossl.com/v2/DV90"

    // External Account Binding (EAB) credentials
    eab {
        kid "your-eab-kid"
        hmac-key "your-base64url-encoded-hmac-key"
    }
}
```

### SAN (Subject Alternative Name) Certificates

Zentinel supports single certificates covering multiple domains. The renewal scheduler automatically handles this by only checking the primary domain (the first one in the list) to avoid redundant renewal requests and infinite loops.

```kdl
acme {
    email "admin@example.com"
    domains "example.com" "api.example.com" "www.example.com"
}
```

### `acme/client.rs`

1. **Create Order** - Request certificate with DNS-01 challenges
2. **Create TXT Records** - Provider creates `_acme-challenge.{domain}` records
3. **Wait for Propagation** - Query public DNS for record visibility
4. **Notify ACME Server** - Challenge is ready for validation
5. **Wait for Validation** - ACME server verifies records
6. **Cleanup** - Delete TXT records (always, even on failure)
7. **Finalize** - Submit CSR and retrieve certificate

### `acme/client.rs`

The `AcmeClient` wraps the `instant-acme` library and provides:

- **Account Management**: Creates or loads ACME accounts with Let's Encrypt
- **Order Creation**: Initiates certificate orders for configured domains
- **Challenge Handling**: Coordinates HTTP-01 challenge validation
- **Certificate Finalization**: Generates CSRs and retrieves issued certificates

Key methods:
- `init_account()` - Initialize or restore ACME account
- `create_order()` - Create certificate order with HTTP-01 challenges
- `create_order_dns01()` - Create certificate order with DNS-01 challenges
- `validate_challenge()` - Notify ACME server challenge is ready
- `wait_for_order_ready()` - Poll until order is validated
- `finalize_order()` - Submit CSR and get certificate
- `needs_renewal()` - Check if certificate needs renewal

### `acme/challenge.rs`

The `ChallengeManager` handles HTTP-01 challenge responses:

```rust
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

impl ChallengeManager {
    pub fn add_challenge(&self, token: &str, key_authorization: &str);
    pub fn get_response(&self, token: &str) -> Option<String>;
    pub fn remove_challenge(&self, token: &str);
    pub fn extract_token(path: &str) -> Option<&str>;
}
```

Uses `DashMap` for concurrent, lock-free access to active challenges.

### `acme/storage.rs`

The `CertificateStorage` manages persistent storage:

```
storage/
├── credentials.json     # Serialized AccountCredentials (opaque)
└── domains/
    └── example.com/
        ├── cert.pem     # Certificate chain
        ├── key.pem      # Private key (mode 0600)
        └── meta.json    # Expiry, issued date, domains
```

Key methods:
- `load_certificate()` / `save_certificate()` - Certificate persistence
- `load_credentials_json()` / `save_credentials_json()` - Account credentials
- `needs_renewal()` - Check if within renewal window
- `certificate_paths()` - Get paths for cert/key files

### `acme/scheduler.rs`

The `RenewalScheduler` runs as a background task orchestrating renewal timing, ARI refresh scheduling, fallback policy, and TLS hot-reload:

- **Event-Driven Deadline Loop**: Uses dynamic sleep intervals (`next_wakeup`) to trigger at the earliest of the selected ARI renewal deadline, the next ARI refresh deadline, or the fallback polling interval (default 12 hours, minimum 1 hour).
- **ARI Renewal Windows (RFC 9773)**: When supported by the CA, renewal is scheduled within the CA-suggested renewal window (`suggestedWindow`). If the window starts in the past (e.g. for a revoked certificate), renewal is attempted immediately.
- **Refresh Lifecycle & `Retry-After`**: Periodically refreshes renewal information using the CA server's `Retry-After` hint to discover changes to the renewal window. Refresh intervals are clamped between 1 minute and 24 hours (RFC 9773 §4.3.2). Upcoming refreshes never delay an already-due renewal.
- **Fallback Policy (`renew-before-days`)**: Not all ACME servers support ARI. When ARI is explicitly unsupported, or when ARI information is temporarily unavailable and no cached window exists, Zentinel continues using the configured `renew-before-days` policy.
- **Error Recovery & Backoff (RFC 9773 §4.3.3)**:
  - Every refresh failure either schedules a future retry or clears obsolete deadlines; no overdue refresh is left in the past to prevent tight wakeup loops.
  - Temporary failures (timeouts, network errors, 5xx responses) trigger bounded exponential backoff (1m for 1st failure, 2m for 2nd, 4m for 3rd).
  - Exhausted retries (>3 consecutive failures) transition to a long-term retry schedule (~6 hours).
  - Long-term errors (non-5xx HTTP responses including 404, connection refused, DNS resolution failures, invalid `suggestedWindow` where `end <= start`) schedule long-term retries (~6 hours) without tight polling.
  - **HTTP status classification & dependency boundary**: `instant-acme 0.8.5` parses Problem JSON (RFC 7807/RFC 8555) and exposes `problem.status: Option<u16>` as deserialized from the response body; the raw transport-level HTTP status code header is not retained by the library when Problem `status` is absent or when responses fail Problem parsing (such as HTML error pages or missing `Retry-After`). Responses containing `status: 500..=599` are classified as temporary; non-5xx (including 404), omitted Problem `status`, missing `Retry-After`, and unparseable problem responses fall back conservatively to long-term errors (~6 hours). Crucially, none of these are mistaken for explicit ARI capability detection; only explicit `instant_acme::Error::Unsupported` marks ARI capability as `Unsupported`.
  - Explicit unsupported status (`instant_acme::Error::Unsupported`) switches capability to `Unsupported`, clears stale ARI windows, and activates `renew-before-days` fallback.
  - Expired or missing certificates clear obsolete ARI state and fall back directly to immediate renewal / fallback thresholds.
  - Transient refresh failures preserve any previously cached valid window and renewal deadline for the active certificate.
- **Order Linking with `replaces`**: When a valid predecessor certificate exists, its identifier can be extracted, and the CA supports ARI, renewal orders include `replaces(cert_id)` for both HTTP-01 and DNS-01 flows. If an order with `replaces` fails because the server rejects predecessor replacement, the client cleanly falls back to ordering without `replaces`.
- **Active Certificate Identity**: After renewal succeeds, the scheduler switches to tracking the newly issued certificate, invalidates predecessor scheduling state, and promptly requests ARI for the new certificate.

### `acme/error.rs`

ACME-specific error types:

```rust
pub enum AcmeError {
    AccountCreation(String),
    NoAccount,
    OrderCreation(String),
    NoHttp01Challenge(String),
    NoDns01Challenge(String),         // DNS-01 challenge not available
    NoDnsProvider,                     // DNS-01 requested but no provider configured
    DnsProvider(DnsProviderError),     // DNS provider operation failed
    PropagationTimeout { record: String, elapsed: Duration },
    WildcardRequiresDns01 { domain: String },
    ChallengeValidation { domain: String, message: String },
    Finalization(String),
    CertificateParse(String),
    Timeout(String),
    Storage(StorageError),
    Ari(AriError),                     // RFC 9773 ARI errors
    Unsupported(&'static str),         // ACME feature unsupported (e.g. ARI)
}
```

## Integration Points

### HTTP-01 Challenge Handling

Challenges are handled in `early_request_filter` before any other request processing:

```rust
// In http_trait.rs
if let Some(ref challenge_manager) = self.acme_challenges {
    if let Some(token) = ChallengeManager::extract_token(path) {
        if let Some(key_authorization) = challenge_manager.get_response(token) {
            // Serve challenge response with 200 OK
            // Content-Type: text/plain
        }
    }
}
```

### TLS Hot-Reload

After successful certificate renewal, the scheduler triggers reload:

```rust
if let Some(ref resolver) = self.sni_resolver {
    resolver.reload()?;
}
```

This uses the existing `HotReloadableSniResolver` infrastructure.

### ZentinelProxy Fields

```rust
pub struct ZentinelProxy {
    // ... existing fields ...

    /// ACME challenge manager for HTTP-01 validation
    pub acme_challenges: Option<Arc<ChallengeManager>>,

    /// ACME clients for certificate operations (one per config block)
    pub acme_clients: Vec<Arc<AcmeClient>>,
}
```

## Multi-tenant ACME (SNI Support)

Zentinel supports independent ACME certificate management for SNI blocks. This is ideal for multi-tenant environments where each tenant has its own domain and requires a separate certificate with potentially different account details or challenge types.

### Independent Renewal Schedulers

When multiple ACME blocks are configured (root level or within SNI blocks), Zentinel spawns independent background schedulers for each. This ensures that a failure or delay in one tenant's certificate issuance (e.g., waiting for DNS propagation) does not block or impact the renewal process of other tenants.

### Implicit Hostname Derivation

For better usability, SNI blocks with ACME can automatically derive their routing hostnames from the ACME domain list if explicit `hostnames` are not provided.

```kdl
listeners {
    listener "https" {
        tls {
            // Root certificate (fallback)
            acme {
                email "admin@example.com"
                domains "example.com"
            }

            // Tenant A - using HTTP-01
            sni {
                acme {
                    email "tenant-a@example.com"
                    domains "tenant-a.com"
                }
            }

            // Tenant B - using DNS-01 for wildcard
            sni {
                acme {
                    email "tenant-b@example.com"
                    domains "*.tenant-b.com" "tenant-b.com"
                    challenge-type "dns-01"
                    dns-provider { ... }
                }
            }
        }
    }
}
```

### Global Domain Validation

To prevent storage path collisions and race conditions, Zentinel enforces global uniqueness for ACME-managed domains. A domain cannot appear in more than one ACME block across the entire configuration.

## Configuration

ACME is configured within the `tls {}` block of a listener or an `sni {}` block.

### HTTP-01 Challenge (Default)

```kdl
listeners {
    listener "https" address="0.0.0.0:443" {
        tls {
            acme {
                email "admin@example.com"
                domains "example.com" "www.example.com"
                staging #false
                storage "/var/lib/zentinel/acme"
                renew-before-days 30
            }
        }
    }
}
```

### DNS-01 Challenge (For Wildcard Certificates)

```kdl
listeners {
    listener "https" address="0.0.0.0:443" {
        tls {
            acme {
                email "admin@example.com"
                domains "example.com" "*.example.com"
                staging #false
                storage "/var/lib/zentinel/acme"
                renew-before-days 30
                challenge-type "dns-01"

                dns-provider {
                    type "hetzner"
                    credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
                    api-timeout-secs 30

                    propagation {
                        initial-delay-secs 10
                        check-interval-secs 5
                        timeout-secs 120
                        nameservers "8.8.8.8" "1.1.1.1"
                    }
                }
            }
        }
    }
}
```

### Webhook Provider (Custom DNS Integration)

```kdl
dns-provider {
    type "webhook"
    url "https://dns-api.internal/v1"
    auth-header "X-API-Key"
    credentials-file "/etc/zentinel/secrets/dns-webhook.json"
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `email` | string | required | Contact email for Let's Encrypt account |
| `domains` | string[] | required | Domains to include in certificate |
| `staging` | bool | `false` | Use Let's Encrypt staging environment |
| `storage` | path | `/var/lib/zentinel/acme` | Directory for certificates and credentials |
| `renew-before-days` | u32 | `30` | Days before expiry to trigger renewal |
| `challenge-type` | string | `"http-01"` | Challenge type: `http-01` or `dns-01` |
| `key-type` | string | `"ecdsa-p256"` | Certificate key type: `ecdsa-p256`, `ecdsa-p384` |
| `dns-provider` | block | - | DNS provider config (required for dns-01) |

### Certificate Key Types

Zentinel allows specifying the encryption algorithm and key size for ACME certificates.

| Value | Description |
|-------|-------------|
| `ecdsa-p256` | ECDSA with NIST P-256 curve (Default, fast and secure) |
| `ecdsa-p384` | ECDSA with NIST P-384 curve (Higher security strength) |

```kdl
acme {
    email "admin@example.com"
    domains "example.com"
    
    // Use high-strength ECDSA
    key-type "ecdsa-p384"
}
```

### DNS Provider Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `type` | string | required | Provider type: `hetzner`, `webhook` |
| `credentials-file` | path | - | Path to credentials file |
| `credentials-env` | string | - | Environment variable with credentials |
| `api-timeout-secs` | u64 | `30` | API request timeout |

### Propagation Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `initial-delay-secs` | u64 | `10` | Wait before first propagation check |
| `check-interval-secs` | u64 | `5` | Interval between checks |
| `timeout-secs` | u64 | `120` | Max time to wait for propagation |
| `nameservers` | string[] | public DNS | DNS servers to query for propagation |

### Credential File Formats

**JSON Token Format:**
```json
{"token": "your-api-token"}
```

**JSON Key/Secret Format:**
```json
{"api_key": "key", "api_secret": "secret"}
```

**Plain Text:**
```
your-api-token
```

### Validation Rules

- Email must be a valid email address
- At least one domain is required
- When `acme` is configured, `cert_file` and `key_file` are optional
- Manual certificates and ACME can coexist (manual takes precedence if both present)
- **Wildcard domains require `challenge-type "dns-01"`**
- **DNS-01 requires a `dns-provider` block**

## Security Considerations

1. **Storage Permissions**: Certificate storage directory is created with mode `0700`, private keys with mode `0600`

2. **Staging Environment**: Use `staging true` for testing to avoid rate limits

3. **Account Credentials**: The `credentials.json` file contains the ACME account private key and should be protected

4. **Challenge Tokens**: Challenge tokens are short-lived and automatically cleaned up after validation

## Dependencies

- `instant-acme` - ACME protocol implementation
- `rcgen` - CSR generation
- `x509-parser` - Certificate parsing for expiry extraction
- `dashmap` - Concurrent challenge storage
- `hickory-resolver` - DNS propagation checking (DNS-01)
- `reqwest` - HTTP client for DNS provider APIs (DNS-01)

## Future Improvements

Phase 2 (completed in v0.4.0):
- ✅ DNS-01 challenge support
- ✅ Wildcard certificates
- ✅ Hetzner DNS provider
- ✅ Generic webhook provider

Phase 3 (planned):
- Multiple certificate authorities
- Certificate transparency logging
- OCSP stapling integration
- Distributed challenge coordination
- Certificate inventory API
- Additional DNS providers (Cloudflare, Route53, etc.)
