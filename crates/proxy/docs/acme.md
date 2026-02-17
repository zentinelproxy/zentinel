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
│  │  Background task checking certificates every 12 hours         │  │
│  │  Triggers renewal when within renew_before_days of expiry     │  │
│  │  Supports both HTTP-01 and DNS-01 renewal flows               │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Module Structure

### `acme/mod.rs`

Module exports and public API:

```rust
pub use challenge::ChallengeManager;
pub use client::AcmeClient;
pub use error::AcmeError;
pub use scheduler::RenewalScheduler;
pub use storage::CertificateStorage;

// DNS-01 challenge support
pub mod dns;
```

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
| `webhook` | Generic webhook for custom DNS integrations |

#### DNS-01 Challenge Flow

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

The `RenewalScheduler` runs as a background task:

- Default check interval: 12 hours (configurable, minimum 1 hour)
- Initial check after 10 second startup delay
- Triggers renewal when certificate expires within `renew_before_days`
- Triggers TLS hot-reload after successful renewal

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

    /// ACME client for certificate operations
    pub acme_client: Option<Arc<AcmeClient>>,
}
```

## Configuration

ACME is configured within the `tls {}` block of a listener.

### HTTP-01 Challenge (Default)

```kdl
listeners {
    listener "https" address="0.0.0.0:443" {
        tls {
            acme {
                email "admin@example.com"
                domains "example.com" "www.example.com"
                staging false
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
                staging false
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
| `dns-provider` | block | - | DNS provider config (required for dns-01) |

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
