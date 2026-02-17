# Rust Coding Standards

> Minimum Rust version: **1.92.0** (Edition 2021)
> Last updated: 2026-01-13

These standards apply to all Rust code in Zentinel. They enforce the [Manifesto](../../MANIFESTO.md) principles of **explicit behavior**, **bounded resources**, and **production correctness**.

**Related rules:**
- [project.md](project.md) — Zentinel-specific architecture rules
- [patterns.md](patterns.md) — Code patterns for Pingora, agents, config
- [workflow.md](workflow.md) — Commands and processes

---

## Modern API Usage (Rust 1.85+)

Prefer modern, idiomatic APIs over manual implementations:

### Arithmetic Operations

```rust
// GOOD: Use div_ceil() for ceiling division (1.73+)
let pages = total_items.div_ceil(items_per_page);

// BAD: Manual ceiling division
let pages = (total_items + items_per_page - 1) / items_per_page;
```

### Collection Entry API

```rust
// GOOD: Use or_default() when inserting default values (1.86+)
map.entry(key).or_default().push(value);

// BAD: Explicit default construction
map.entry(key).or_insert_with(Vec::new).push(value);
```

### Default Derivation

```rust
// GOOD: Use #[default] attribute on enum variants (1.62+)
#[derive(Default)]
pub enum Status {
    #[default]
    Pending,
    Active,
    Completed,
}

// BAD: Manual Default impl for simple cases
impl Default for Status {
    fn default() -> Self {
        Self::Pending
    }
}
```

### Option/Result Helpers

```rust
// GOOD: Use is_none_or() for cleaner conditionals (1.82+)
if value.is_none_or(|v| v.is_empty()) { ... }

// BAD: Manual pattern matching
if value.is_none() || value.as_ref().map_or(false, |v| v.is_empty()) { ... }
```

### Synchronization

```rust
// AVAILABLE: RwLockWriteGuard::downgrade() (1.92+)
// Use when you need to modify then continue reading
let mut guard = lock.write().unwrap();
*guard = new_value;
let read_guard = guard.downgrade(); // Keep read access without releasing lock
```

---

## Error Handling

### Use the `?` Operator

```rust
// GOOD: Propagate errors with ?
fn process() -> Result<Data, Error> {
    let file = File::open(path)?;
    let data = parse(&file)?;
    Ok(data)
}

// BAD: Manual match or unwrap
fn process() -> Result<Data, Error> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(e.into()),
    };
    // ...
}
```

### Avoid `unwrap()` and `expect()` in Library Code

```rust
// GOOD: Return Result and let caller handle
pub fn parse_config(path: &Path) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)?;
    toml::from_str(&content).map_err(ConfigError::Parse)
}

// BAD: Panicking in library code
pub fn parse_config(path: &Path) -> Config {
    let content = fs::read_to_string(path).expect("failed to read");
    toml::from_str(&content).unwrap()
}
```

### Use `anyhow` for Applications, `thiserror` for Libraries

```rust
// Library crate: Define typed errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid config format: {0}")]
    Parse(#[from] toml::de::Error),
}

// Application crate: Use anyhow for convenience
fn main() -> anyhow::Result<()> {
    let config = load_config()?;
    run(config)?;
    Ok(())
}
```

---

## Memory and Performance

### Prefer References Over Cloning

```rust
// GOOD: Accept references when ownership isn't needed
fn process(data: &str) -> Result<(), Error> { ... }

// BAD: Unnecessary ownership transfer
fn process(data: String) -> Result<(), Error> { ... }
```

### Use `Cow` for Flexible Ownership

```rust
// GOOD: Avoid allocation when not needed
fn normalize(input: &str) -> Cow<'_, str> {
    if input.contains(' ') {
        Cow::Owned(input.replace(' ', "_"))
    } else {
        Cow::Borrowed(input)
    }
}
```

### Avoid Allocation in Hot Paths

```rust
// GOOD: Reuse buffers
let mut buffer = String::with_capacity(1024);
for item in items {
    buffer.clear();
    write!(&mut buffer, "{}", item)?;
    process(&buffer)?;
}

// BAD: Allocate per iteration
for item in items {
    let s = format!("{}", item);
    process(&s)?;
}
```

### Use `Arc` Only When Needed

```rust
// GOOD: Use references when lifetime is clear
fn process(config: &Config) { ... }

// Use Arc only for shared ownership across threads
let shared = Arc::new(config);
let handle = thread::spawn({
    let shared = Arc::clone(&shared);
    move || use_config(&shared)
});
```

---

## Async Code

### Prefer `async fn` Over Manual Futures

```rust
// GOOD: Use async fn
async fn fetch_data(url: &str) -> Result<Data, Error> {
    let response = client.get(url).send().await?;
    response.json().await.map_err(Into::into)
}

// BAD: Manual future implementation for simple cases
fn fetch_data(url: &str) -> impl Future<Output = Result<Data, Error>> {
    // ...
}
```

### Use Structured Concurrency

```rust
// GOOD: Use tokio::join! for concurrent operations
let (users, posts) = tokio::join!(
    fetch_users(),
    fetch_posts()
);

// BAD: Sequential when concurrent is possible
let users = fetch_users().await?;
let posts = fetch_posts().await?;
```

### Cancel Safety

```rust
// Document cancellation behavior
/// Fetches user data.
///
/// # Cancel Safety
///
/// This function is cancel-safe. If cancelled, no partial
/// state is left behind.
async fn fetch_user(id: UserId) -> Result<User, Error> { ... }
```

---

## Type Design

### Use Newtypes for Domain Concepts

```rust
// GOOD: Type-safe identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderId(u64);

// BAD: Raw primitives that can be confused
fn process(user_id: u64, order_id: u64) { ... } // Easy to swap by accident
```

### Use `#[must_use]` for Important Return Values

```rust
#[must_use = "iterator adaptors are lazy and do nothing unless consumed"]
pub fn filter_active(users: Vec<User>) -> impl Iterator<Item = User> {
    users.into_iter().filter(|u| u.is_active)
}
```

### Prefer Enums Over Booleans

```rust
// GOOD: Self-documenting
pub enum Visibility {
    Public,
    Private,
}

fn create_post(content: &str, visibility: Visibility) { ... }

// BAD: Unclear meaning
fn create_post(content: &str, is_public: bool) { ... }
```

---

## Testing

### Test Module Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Helper functions for tests
    fn create_test_config() -> Config {
        Config {
            // Use explicit field initialization, not ..Default::default()
            field1: value1,
            field2: value2,
        }
    }

    #[test]
    fn test_descriptive_name_describing_behavior() {
        // Arrange
        let config = create_test_config();

        // Act
        let result = process(&config);

        // Assert
        assert_eq!(result, expected);
    }
}
```

### Avoid `..Default::default()` in Tests

```rust
// GOOD: Explicit field initialization (catches missing fields at compile time)
fn test_route_config() -> RouteConfig {
    RouteConfig {
        id: "test".to_string(),
        priority: Priority::Normal,
        upstream: None,
        // All fields explicitly set
    }
}

// BAD: Hides missing fields, breaks when struct changes
let config = RouteConfig {
    id: "test".to_string(),
    ..Default::default()
};
```

### Use `#[tokio::test]` for Async Tests

```rust
#[tokio::test]
async fn test_async_operation() {
    let result = async_function().await;
    assert!(result.is_ok());
}
```

---

## Documentation

### Document Public APIs

```rust
/// Processes incoming HTTP requests through the proxy pipeline.
///
/// # Arguments
///
/// * `request` - The incoming HTTP request to process
/// * `config` - Route configuration for this request
///
/// # Returns
///
/// The proxied response, or an error if processing failed.
///
/// # Errors
///
/// Returns `ProxyError::Upstream` if the backend is unreachable.
/// Returns `ProxyError::Timeout` if the request times out.
///
/// # Examples
///
/// ```
/// let response = proxy.process(request, &config).await?;
/// ```
pub async fn process(
    &self,
    request: Request,
    config: &RouteConfig,
) -> Result<Response, ProxyError> {
    // ...
}
```

### Use `//!` for Module Documentation

```rust
//! HTTP caching infrastructure for Zentinel.
//!
//! This module provides response caching using Pingora's cache infrastructure.
//!
//! # Features
//!
//! - Per-route cache configuration
//! - Cache-Control header parsing
//! - TTL calculation
//!
//! # Example
//!
//! ```ignore
//! let cache = CacheManager::new(config);
//! cache.store(key, response).await?;
//! ```
```

---

## Dependencies

### Minimize Dependencies

- Evaluate necessity before adding new dependencies
- Prefer std library features when available
- Check maintenance status and security history

### Feature Flags

```toml
# Cargo.toml - Use feature flags for optional functionality
[features]
default = []
distributed-rate-limit = ["redis", "deadpool-redis"]
kubernetes = ["kube", "k8s-openapi"]
```

---

## Linting and Formatting

### Run Before Committing

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

### Clippy Configuration

Allow specific lints only with justification:

```rust
// Allowed: Complex type is intentional for this API
#[allow(clippy::type_complexity)]
pub type HandlerFn = Box<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response>>>>;
```

---

## Future Considerations (Edition 2024)

These features will be available when we migrate to Rust Edition 2024:

### Let Chains

```rust
// Available in Edition 2024
if let Some(user) = get_user()
    && let Some(email) = user.email
    && email.ends_with("@company.com")
{
    send_notification(&email);
}
```

### Async Closures

```rust
// Available in Edition 2024
let handler = async |request: Request| {
    process(request).await
};
```

---

## Version History

| Date | Rust Version | Changes |
|------|--------------|---------|
| 2026-01-13 | 1.92.0 | Integrated with Zentinel rules structure |
| 2026-01-10 | 1.92.0 | Initial standards, added div_ceil, or_default, RwLock::downgrade |
