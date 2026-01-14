# ACME Automatic Certificate Management

This document describes Sentinel's ACME (Automatic Certificate Management Environment) implementation for automatic TLS certificate issuance and renewal via Let's Encrypt.

## Overview

Sentinel supports automatic TLS certificate management using the ACME protocol (RFC 8555). This eliminates the need for manual certificate management by automatically:

- Requesting certificates from Let's Encrypt
- Completing HTTP-01 domain validation challenges
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
│  │                    ChallengeManager                           │  │
│  │                                                               │  │
│  │  HTTP-01 challenges served from /.well-known/acme-challenge/  │  │
│  │  Handled in early_request_filter before routing               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   RenewalScheduler                            │  │
│  │                                                               │  │
│  │  Background task checking certificates every 12 hours         │  │
│  │  Triggers renewal when within renew_before_days of expiry     │  │
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
```

### `acme/client.rs`

The `AcmeClient` wraps the `instant-acme` library and provides:

- **Account Management**: Creates or loads ACME accounts with Let's Encrypt
- **Order Creation**: Initiates certificate orders for configured domains
- **Challenge Handling**: Coordinates HTTP-01 challenge validation
- **Certificate Finalization**: Generates CSRs and retrieves issued certificates

Key methods:
- `init_account()` - Initialize or restore ACME account
- `create_order()` - Create certificate order, returns challenges
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

### SentinelProxy Fields

```rust
pub struct SentinelProxy {
    // ... existing fields ...

    /// ACME challenge manager for HTTP-01 validation
    pub acme_challenges: Option<Arc<ChallengeManager>>,

    /// ACME client for certificate operations
    pub acme_client: Option<Arc<AcmeClient>>,
}
```

## Configuration

ACME is configured within the `tls {}` block of a listener:

```kdl
listeners {
    listener "https" address="0.0.0.0:443" {
        tls {
            acme {
                email "admin@example.com"
                domains "example.com" "www.example.com"
                staging false
                storage "/var/lib/sentinel/acme"
                renew-before-days 30
            }
        }
    }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `email` | string | required | Contact email for Let's Encrypt account |
| `domains` | string[] | required | Domains to include in certificate |
| `staging` | bool | `false` | Use Let's Encrypt staging environment |
| `storage` | path | `/var/lib/sentinel/acme` | Directory for certificates and credentials |
| `renew-before-days` | u32 | `30` | Days before expiry to trigger renewal |

### Validation Rules

- Email must be a valid email address
- At least one domain is required
- When `acme` is configured, `cert_file` and `key_file` are optional
- Manual certificates and ACME can coexist (manual takes precedence if both present)

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

## Future Improvements

Phase 2 (planned):
- DNS-01 challenge support
- Wildcard certificates
- Multiple certificate authorities
- Certificate transparency logging

Phase 3 (planned):
- OCSP stapling integration
- Distributed challenge coordination
- Certificate inventory API
