//! Hot-path benchmarks for Agent Protocol v2 performance optimizations.
//!
//! These benchmarks measure the performance of P0-P3 optimizations:
//! - P0: Lock-free connection selection
//! - P1: MessagePack vs JSON serialization
//! - P2: SmallVec header optimization
//! - P3: Protocol metrics, connection affinity, zero-copy body streaming

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::hint::black_box;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use smallvec::SmallVec;

// ============================================================================
// P0: Connection Selection Benchmarks
// ============================================================================

/// Benchmark DashMap vs RwLock<HashMap> for agent lookup
fn bench_agent_lookup(c: &mut Criterion) {
    use std::sync::RwLock;

    let mut group = c.benchmark_group("agent_lookup");

    // Setup: Create maps with varying number of agents
    for num_agents in [1, 10, 100, 1000] {
        // DashMap (current implementation)
        let dashmap: DashMap<String, Arc<String>> = DashMap::new();
        for i in 0..num_agents {
            dashmap.insert(format!("agent-{}", i), Arc::new(format!("value-{}", i)));
        }

        // RwLock<HashMap> (old implementation)
        let rwlock_map: RwLock<HashMap<String, Arc<String>>> = RwLock::new(HashMap::new());
        {
            let mut map = rwlock_map.write().unwrap();
            for i in 0..num_agents {
                map.insert(format!("agent-{}", i), Arc::new(format!("value-{}", i)));
            }
        }

        let lookup_key = format!("agent-{}", num_agents / 2);

        group.bench_with_input(
            BenchmarkId::new("dashmap", num_agents),
            &num_agents,
            |b, _| {
                b.iter(|| {
                    let result = dashmap.get(&lookup_key).map(|r| Arc::clone(&*r));
                    black_box(result)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("rwlock_hashmap", num_agents),
            &num_agents,
            |b, _| {
                b.iter(|| {
                    let map = rwlock_map.read().unwrap();
                    let result = map.get(&lookup_key).cloned();
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark atomic vs RwLock for health state caching
fn bench_health_cache(c: &mut Criterion) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::RwLock;

    let mut group = c.benchmark_group("health_cache");

    let atomic_health = AtomicBool::new(true);
    let rwlock_health: RwLock<bool> = RwLock::new(true);

    group.bench_function("atomic_read", |b| {
        b.iter(|| black_box(atomic_health.load(Ordering::Relaxed)))
    });

    group.bench_function("rwlock_read", |b| {
        b.iter(|| black_box(*rwlock_health.read().unwrap()))
    });

    group.bench_function("atomic_write", |b| {
        b.iter(|| atomic_health.store(black_box(true), Ordering::Relaxed))
    });

    group.bench_function("rwlock_write", |b| {
        b.iter(|| *rwlock_health.write().unwrap() = black_box(true))
    });

    group.finish();
}

/// Benchmark atomic timestamp tracking
fn bench_timestamp_tracking(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::RwLock;
    use std::time::Instant;

    let mut group = c.benchmark_group("timestamp_tracking");

    let base_instant = Instant::now();
    let atomic_offset = AtomicU64::new(0);
    let rwlock_instant: RwLock<Instant> = RwLock::new(base_instant);

    group.bench_function("atomic_touch", |b| {
        b.iter(|| {
            let offset = base_instant.elapsed().as_millis() as u64;
            atomic_offset.store(offset, Ordering::Relaxed);
        })
    });

    group.bench_function("rwlock_touch", |b| {
        b.iter(|| {
            *rwlock_instant.write().unwrap() = Instant::now();
        })
    });

    group.bench_function("atomic_read", |b| {
        b.iter(|| {
            let offset = atomic_offset.load(Ordering::Relaxed);
            black_box(base_instant + Duration::from_millis(offset))
        })
    });

    group.bench_function("rwlock_read", |b| {
        b.iter(|| black_box(*rwlock_instant.read().unwrap()))
    });

    group.finish();
}

// ============================================================================
// P1: Serialization Benchmarks
// ============================================================================

/// Sample request headers event for benchmarking
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BenchRequestHeaders {
    correlation_id: String,
    method: String,
    uri: String,
    headers: HashMap<String, Vec<String>>,
    client_ip: String,
    tls_version: Option<String>,
}

impl BenchRequestHeaders {
    fn sample_small() -> Self {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), vec!["example.com".to_string()]);
        headers.insert("user-agent".to_string(), vec!["benchmark/1.0".to_string()]);
        headers.insert("accept".to_string(), vec!["*/*".to_string()]);

        Self {
            correlation_id: "bench-12345".to_string(),
            method: "GET".to_string(),
            uri: "/api/v1/users".to_string(),
            headers,
            client_ip: "192.168.1.100".to_string(),
            tls_version: Some("TLSv1.3".to_string()),
        }
    }

    fn sample_large() -> Self {
        let mut headers = HashMap::new();
        // Typical production request with 20+ headers
        headers.insert("host".to_string(), vec!["api.example.com".to_string()]);
        headers.insert("user-agent".to_string(), vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()]);
        headers.insert("accept".to_string(), vec!["application/json".to_string(), "text/plain".to_string(), "*/*".to_string()]);
        headers.insert("accept-language".to_string(), vec!["en-US,en;q=0.9".to_string()]);
        headers.insert("accept-encoding".to_string(), vec!["gzip, deflate, br".to_string()]);
        headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
        headers.insert("content-length".to_string(), vec!["1024".to_string()]);
        headers.insert("authorization".to_string(), vec!["Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0".to_string()]);
        headers.insert("cookie".to_string(), vec!["session=abc123; tracking=xyz789".to_string()]);
        headers.insert("x-request-id".to_string(), vec!["req-12345-67890".to_string()]);
        headers.insert("x-correlation-id".to_string(), vec!["corr-abcdef-123456".to_string()]);
        headers.insert("x-forwarded-for".to_string(), vec!["203.0.113.195, 70.41.3.18, 150.172.238.178".to_string()]);
        headers.insert("x-forwarded-proto".to_string(), vec!["https".to_string()]);
        headers.insert("x-forwarded-host".to_string(), vec!["api.example.com".to_string()]);
        headers.insert("x-real-ip".to_string(), vec!["203.0.113.195".to_string()]);
        headers.insert("cache-control".to_string(), vec!["no-cache".to_string()]);
        headers.insert("pragma".to_string(), vec!["no-cache".to_string()]);
        headers.insert("origin".to_string(), vec!["https://app.example.com".to_string()]);
        headers.insert("referer".to_string(), vec!["https://app.example.com/dashboard".to_string()]);
        headers.insert("sec-fetch-dest".to_string(), vec!["empty".to_string()]);
        headers.insert("sec-fetch-mode".to_string(), vec!["cors".to_string()]);
        headers.insert("sec-fetch-site".to_string(), vec!["same-site".to_string()]);

        Self {
            correlation_id: "bench-large-12345-67890".to_string(),
            method: "POST".to_string(),
            uri: "/api/v2/orders/create?include=items,shipping&format=json".to_string(),
            headers,
            client_ip: "203.0.113.195".to_string(),
            tls_version: Some("TLSv1.3".to_string()),
        }
    }
}

/// Benchmark JSON vs MessagePack serialization
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    let small_event = BenchRequestHeaders::sample_small();
    let large_event = BenchRequestHeaders::sample_large();

    // JSON serialization
    group.bench_function("json_small", |b| {
        b.iter(|| black_box(serde_json::to_vec(&small_event).unwrap()))
    });

    group.bench_function("json_large", |b| {
        b.iter(|| black_box(serde_json::to_vec(&large_event).unwrap()))
    });

    // MessagePack serialization (if feature enabled)
    #[cfg(feature = "binary-uds")]
    {
        group.bench_function("msgpack_small", |b| {
            b.iter(|| black_box(rmp_serde::to_vec(&small_event).unwrap()))
        });

        group.bench_function("msgpack_large", |b| {
            b.iter(|| black_box(rmp_serde::to_vec(&large_event).unwrap()))
        });
    }

    // Measure serialized sizes
    let json_small = serde_json::to_vec(&small_event).unwrap();
    let json_large = serde_json::to_vec(&large_event).unwrap();
    println!("\nSerialized sizes:");
    println!("  JSON small: {} bytes", json_small.len());
    println!("  JSON large: {} bytes", json_large.len());

    #[cfg(feature = "binary-uds")]
    {
        let msgpack_small = rmp_serde::to_vec(&small_event).unwrap();
        let msgpack_large = rmp_serde::to_vec(&large_event).unwrap();
        println!("  MessagePack small: {} bytes ({:.1}% of JSON)",
            msgpack_small.len(),
            msgpack_small.len() as f64 / json_small.len() as f64 * 100.0);
        println!("  MessagePack large: {} bytes ({:.1}% of JSON)",
            msgpack_large.len(),
            msgpack_large.len() as f64 / json_large.len() as f64 * 100.0);
    }

    group.finish();
}

/// Benchmark JSON vs MessagePack deserialization
fn bench_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialization");

    let small_event = BenchRequestHeaders::sample_small();
    let large_event = BenchRequestHeaders::sample_large();

    let json_small = serde_json::to_vec(&small_event).unwrap();
    let json_large = serde_json::to_vec(&large_event).unwrap();

    group.bench_function("json_small", |b| {
        b.iter(|| {
            black_box(serde_json::from_slice::<BenchRequestHeaders>(&json_small).unwrap())
        })
    });

    group.bench_function("json_large", |b| {
        b.iter(|| {
            black_box(serde_json::from_slice::<BenchRequestHeaders>(&json_large).unwrap())
        })
    });

    #[cfg(feature = "binary-uds")]
    {
        let msgpack_small = rmp_serde::to_vec(&small_event).unwrap();
        let msgpack_large = rmp_serde::to_vec(&large_event).unwrap();

        group.bench_function("msgpack_small", |b| {
            b.iter(|| {
                black_box(rmp_serde::from_slice::<BenchRequestHeaders>(&msgpack_small).unwrap())
            })
        });

        group.bench_function("msgpack_large", |b| {
            b.iter(|| {
                black_box(rmp_serde::from_slice::<BenchRequestHeaders>(&msgpack_large).unwrap())
            })
        });
    }

    group.finish();
}

// ============================================================================
// P2: Header Allocation Benchmarks
// ============================================================================

type HeaderValues = SmallVec<[String; 1]>;
type OptimizedHeaderMap = HashMap<String, HeaderValues>;

/// Benchmark SmallVec vs Vec for header values
fn bench_header_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_allocation");

    // Single value (most common case)
    group.bench_function("vec_single_value", |b| {
        b.iter(|| {
            let v: Vec<String> = vec!["application/json".to_string()];
            black_box(v)
        })
    });

    group.bench_function("smallvec_single_value", |b| {
        b.iter(|| {
            let v: HeaderValues = SmallVec::from_iter(["application/json".to_string()]);
            black_box(v)
        })
    });

    // Multiple values (less common)
    group.bench_function("vec_multi_value", |b| {
        b.iter(|| {
            let v: Vec<String> = vec![
                "text/html".to_string(),
                "application/json".to_string(),
                "*/*".to_string(),
            ];
            black_box(v)
        })
    });

    group.bench_function("smallvec_multi_value", |b| {
        b.iter(|| {
            let v: HeaderValues = SmallVec::from_iter([
                "text/html".to_string(),
                "application/json".to_string(),
                "*/*".to_string(),
            ]);
            black_box(v)
        })
    });

    group.finish();
}

/// Benchmark header map creation with typical request headers
fn bench_header_map_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_map_creation");

    // Standard Vec-based headers
    group.bench_function("vec_map_20_headers", |b| {
        b.iter(|| {
            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            map.insert("host".to_string(), vec!["example.com".to_string()]);
            map.insert("user-agent".to_string(), vec!["benchmark/1.0".to_string()]);
            map.insert("accept".to_string(), vec!["application/json".to_string()]);
            map.insert("accept-language".to_string(), vec!["en-US".to_string()]);
            map.insert("accept-encoding".to_string(), vec!["gzip".to_string()]);
            map.insert("content-type".to_string(), vec!["application/json".to_string()]);
            map.insert("content-length".to_string(), vec!["1024".to_string()]);
            map.insert("authorization".to_string(), vec!["Bearer token".to_string()]);
            map.insert("cookie".to_string(), vec!["session=abc".to_string()]);
            map.insert("x-request-id".to_string(), vec!["req-123".to_string()]);
            map.insert("x-correlation-id".to_string(), vec!["corr-456".to_string()]);
            map.insert("x-forwarded-for".to_string(), vec!["1.2.3.4".to_string()]);
            map.insert("x-forwarded-proto".to_string(), vec!["https".to_string()]);
            map.insert("x-real-ip".to_string(), vec!["1.2.3.4".to_string()]);
            map.insert("cache-control".to_string(), vec!["no-cache".to_string()]);
            map.insert("pragma".to_string(), vec!["no-cache".to_string()]);
            map.insert("origin".to_string(), vec!["https://app.example.com".to_string()]);
            map.insert("referer".to_string(), vec!["https://app.example.com/".to_string()]);
            map.insert("sec-fetch-dest".to_string(), vec!["empty".to_string()]);
            map.insert("sec-fetch-mode".to_string(), vec!["cors".to_string()]);
            black_box(map)
        })
    });

    // SmallVec-based headers
    group.bench_function("smallvec_map_20_headers", |b| {
        b.iter(|| {
            let mut map: OptimizedHeaderMap = HashMap::new();
            map.insert("host".to_string(), SmallVec::from_iter(["example.com".to_string()]));
            map.insert("user-agent".to_string(), SmallVec::from_iter(["benchmark/1.0".to_string()]));
            map.insert("accept".to_string(), SmallVec::from_iter(["application/json".to_string()]));
            map.insert("accept-language".to_string(), SmallVec::from_iter(["en-US".to_string()]));
            map.insert("accept-encoding".to_string(), SmallVec::from_iter(["gzip".to_string()]));
            map.insert("content-type".to_string(), SmallVec::from_iter(["application/json".to_string()]));
            map.insert("content-length".to_string(), SmallVec::from_iter(["1024".to_string()]));
            map.insert("authorization".to_string(), SmallVec::from_iter(["Bearer token".to_string()]));
            map.insert("cookie".to_string(), SmallVec::from_iter(["session=abc".to_string()]));
            map.insert("x-request-id".to_string(), SmallVec::from_iter(["req-123".to_string()]));
            map.insert("x-correlation-id".to_string(), SmallVec::from_iter(["corr-456".to_string()]));
            map.insert("x-forwarded-for".to_string(), SmallVec::from_iter(["1.2.3.4".to_string()]));
            map.insert("x-forwarded-proto".to_string(), SmallVec::from_iter(["https".to_string()]));
            map.insert("x-real-ip".to_string(), SmallVec::from_iter(["1.2.3.4".to_string()]));
            map.insert("cache-control".to_string(), SmallVec::from_iter(["no-cache".to_string()]));
            map.insert("pragma".to_string(), SmallVec::from_iter(["no-cache".to_string()]));
            map.insert("origin".to_string(), SmallVec::from_iter(["https://app.example.com".to_string()]));
            map.insert("referer".to_string(), SmallVec::from_iter(["https://app.example.com/".to_string()]));
            map.insert("sec-fetch-dest".to_string(), SmallVec::from_iter(["empty".to_string()]));
            map.insert("sec-fetch-mode".to_string(), SmallVec::from_iter(["cors".to_string()]));
            black_box(map)
        })
    });

    group.finish();
}

/// Benchmark header iteration (iter_flat pattern)
fn bench_header_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_iteration");

    // Create sample headers
    let mut vec_headers: HashMap<String, Vec<String>> = HashMap::new();
    vec_headers.insert("accept".to_string(), vec!["text/html".to_string(), "application/json".to_string()]);
    vec_headers.insert("host".to_string(), vec!["example.com".to_string()]);
    vec_headers.insert("user-agent".to_string(), vec!["benchmark/1.0".to_string()]);
    for i in 0..17 {
        vec_headers.insert(format!("x-custom-{}", i), vec![format!("value-{}", i)]);
    }

    let mut smallvec_headers: OptimizedHeaderMap = HashMap::new();
    smallvec_headers.insert("accept".to_string(), SmallVec::from_iter(["text/html".to_string(), "application/json".to_string()]));
    smallvec_headers.insert("host".to_string(), SmallVec::from_iter(["example.com".to_string()]));
    smallvec_headers.insert("user-agent".to_string(), SmallVec::from_iter(["benchmark/1.0".to_string()]));
    for i in 0..17 {
        smallvec_headers.insert(format!("x-custom-{}", i), SmallVec::from_iter([format!("value-{}", i)]));
    }

    // iter_flat for Vec-based
    group.bench_function("vec_iter_flat", |b| {
        b.iter(|| {
            let count: usize = vec_headers
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
                .count();
            black_box(count)
        })
    });

    // iter_flat for SmallVec-based
    group.bench_function("smallvec_iter_flat", |b| {
        b.iter(|| {
            let count: usize = smallvec_headers
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
                .count();
            black_box(count)
        })
    });

    // Collect to Vec (simulating gRPC conversion)
    group.bench_function("vec_collect_to_grpc", |b| {
        b.iter(|| {
            let headers: Vec<(&str, &str)> = vec_headers
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
                .collect();
            black_box(headers)
        })
    });

    group.bench_function("smallvec_collect_to_grpc", |b| {
        b.iter(|| {
            let headers: Vec<(&str, &str)> = smallvec_headers
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
                .collect();
            black_box(headers)
        })
    });

    group.finish();
}

// ============================================================================
// P3: Body Streaming Benchmarks
// ============================================================================

/// Body chunk for benchmarking
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BenchBodyChunk {
    correlation_id: String,
    data: String,  // Base64 for JSON
    is_last: bool,
    chunk_index: u32,
}

/// Binary body chunk with serde_bytes
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BenchBinaryBodyChunk {
    correlation_id: String,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    is_last: bool,
    chunk_index: u32,
}

/// Benchmark body chunk serialization: base64 vs binary
fn bench_body_chunk_serialization(c: &mut Criterion) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let mut group = c.benchmark_group("body_chunk_serialization");

    // Test with various chunk sizes
    for size in [1024, 4096, 16384, 65536] {
        group.throughput(Throughput::Bytes(size as u64));

        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let base64_data = STANDARD.encode(&data);

        let json_chunk = BenchBodyChunk {
            correlation_id: "bench-123".to_string(),
            data: base64_data,
            is_last: false,
            chunk_index: 0,
        };

        let binary_chunk = BenchBinaryBodyChunk {
            correlation_id: "bench-123".to_string(),
            data: data.clone(),
            is_last: false,
            chunk_index: 0,
        };

        group.bench_with_input(
            BenchmarkId::new("json_base64", size),
            &size,
            |b, _| {
                b.iter(|| black_box(serde_json::to_vec(&json_chunk).unwrap()))
            },
        );

        #[cfg(feature = "binary-uds")]
        {
            group.bench_with_input(
                BenchmarkId::new("msgpack_binary", size),
                &size,
                |b, _| {
                    b.iter(|| black_box(rmp_serde::to_vec(&binary_chunk).unwrap()))
                },
            );
        }
    }

    group.finish();
}

/// Benchmark body chunk deserialization
fn bench_body_chunk_deserialization(c: &mut Criterion) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let mut group = c.benchmark_group("body_chunk_deserialization");

    for size in [1024, 4096, 16384, 65536] {
        group.throughput(Throughput::Bytes(size as u64));

        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let base64_data = STANDARD.encode(&data);

        let json_chunk = BenchBodyChunk {
            correlation_id: "bench-123".to_string(),
            data: base64_data,
            is_last: false,
            chunk_index: 0,
        };

        let binary_chunk = BenchBinaryBodyChunk {
            correlation_id: "bench-123".to_string(),
            data: data.clone(),
            is_last: false,
            chunk_index: 0,
        };

        let json_bytes = serde_json::to_vec(&json_chunk).unwrap();

        group.bench_with_input(
            BenchmarkId::new("json_base64", size),
            &size,
            |b, _| {
                b.iter(|| black_box(serde_json::from_slice::<BenchBodyChunk>(&json_bytes).unwrap()))
            },
        );

        #[cfg(feature = "binary-uds")]
        {
            let msgpack_bytes = rmp_serde::to_vec(&binary_chunk).unwrap();

            group.bench_with_input(
                BenchmarkId::new("msgpack_binary", size),
                &size,
                |b, _| {
                    b.iter(|| black_box(rmp_serde::from_slice::<BenchBinaryBodyChunk>(&msgpack_bytes).unwrap()))
                },
            );
        }
    }

    group.finish();
}

// ============================================================================
// P3: Protocol Metrics Benchmarks
// ============================================================================

/// Benchmark protocol metrics overhead
fn bench_protocol_metrics(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut group = c.benchmark_group("protocol_metrics");

    let counter = AtomicU64::new(0);

    group.bench_function("counter_increment", |b| {
        b.iter(|| counter.fetch_add(1, Ordering::Relaxed))
    });

    group.bench_function("counter_read", |b| {
        b.iter(|| black_box(counter.load(Ordering::Relaxed)))
    });

    // Simulate histogram bucket lookup
    let buckets = [10u64, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
    let bucket_counts: Vec<AtomicU64> = (0..buckets.len()).map(|_| AtomicU64::new(0)).collect();

    group.bench_function("histogram_record", |b| {
        let mut value = 0u64;
        b.iter(|| {
            value = (value + 37) % 15000; // Simulate varying latencies
            let bucket_idx = buckets.iter().position(|&b| value <= b).unwrap_or(buckets.len() - 1);
            bucket_counts[bucket_idx].fetch_add(1, Ordering::Relaxed);
        })
    });

    group.finish();
}

// ============================================================================
// P3: Connection Affinity Benchmarks
// ============================================================================

/// Benchmark connection affinity lookup
fn bench_connection_affinity(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_affinity");

    // Setup: Create affinity map with varying number of entries
    for num_entries in [10, 100, 1000, 10000] {
        let affinity: DashMap<String, Arc<String>> = DashMap::new();
        for i in 0..num_entries {
            affinity.insert(format!("corr-{}", i), Arc::new(format!("conn-{}", i % 4)));
        }

        let lookup_key = format!("corr-{}", num_entries / 2);
        let missing_key = format!("corr-{}", num_entries + 1);

        group.bench_with_input(
            BenchmarkId::new("lookup_hit", num_entries),
            &num_entries,
            |b, _| {
                b.iter(|| black_box(affinity.get(&lookup_key)))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("lookup_miss", num_entries),
            &num_entries,
            |b, _| {
                b.iter(|| black_box(affinity.get(&missing_key)))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("insert", num_entries),
            &num_entries,
            |b, _| {
                let key = format!("new-corr-{}", num_entries);
                let value = Arc::new("conn-0".to_string());
                b.iter(|| {
                    affinity.insert(key.clone(), Arc::clone(&value));
                    affinity.remove(&key);
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Combined Hot-Path Benchmark
// ============================================================================

/// Simulate a complete request hot-path
fn bench_full_request_path(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut group = c.benchmark_group("full_request_path");

    // Setup: Simulate pool state
    let agents: DashMap<String, Arc<String>> = DashMap::new();
    agents.insert("waf".to_string(), Arc::new("agent-entry".to_string()));

    let affinity: DashMap<String, Arc<String>> = DashMap::new();
    let health_cached = std::sync::atomic::AtomicBool::new(true);
    let in_flight = AtomicU64::new(0);
    let request_counter = AtomicU64::new(0);

    let headers = BenchRequestHeaders::sample_small();
    let json_payload = serde_json::to_vec(&headers).unwrap();

    #[cfg(feature = "binary-uds")]
    let msgpack_payload = rmp_serde::to_vec(&headers).unwrap();

    // Full path with JSON
    group.bench_function("json_path", |b| {
        b.iter(|| {
            // 1. Agent lookup (DashMap)
            let _agent = agents.get("waf").unwrap();

            // 2. Check affinity
            let _affinity = affinity.get("bench-123");

            // 3. Check health (atomic)
            let _healthy = health_cached.load(Ordering::Relaxed);

            // 4. Increment counters
            request_counter.fetch_add(1, Ordering::Relaxed);
            in_flight.fetch_add(1, Ordering::Relaxed);

            // 5. Serialize (JSON)
            let payload = serde_json::to_vec(&headers).unwrap();

            // 6. Store affinity
            affinity.insert("bench-123".to_string(), Arc::new("conn-0".to_string()));

            // 7. Decrement in-flight
            in_flight.fetch_sub(1, Ordering::Relaxed);

            // 8. Clear affinity
            affinity.remove("bench-123");

            black_box(payload)
        })
    });

    #[cfg(feature = "binary-uds")]
    group.bench_function("msgpack_path", |b| {
        b.iter(|| {
            // 1. Agent lookup (DashMap)
            let _agent = agents.get("waf").unwrap();

            // 2. Check affinity
            let _affinity = affinity.get("bench-123");

            // 3. Check health (atomic)
            let _healthy = health_cached.load(Ordering::Relaxed);

            // 4. Increment counters
            request_counter.fetch_add(1, Ordering::Relaxed);
            in_flight.fetch_add(1, Ordering::Relaxed);

            // 5. Serialize (MessagePack)
            let payload = rmp_serde::to_vec(&headers).unwrap();

            // 6. Store affinity
            affinity.insert("bench-123".to_string(), Arc::new("conn-0".to_string()));

            // 7. Decrement in-flight
            in_flight.fetch_sub(1, Ordering::Relaxed);

            // 8. Clear affinity
            affinity.remove("bench-123");

            black_box(payload)
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    p0_benchmarks,
    bench_agent_lookup,
    bench_health_cache,
    bench_timestamp_tracking,
);

criterion_group!(
    p1_benchmarks,
    bench_serialization,
    bench_deserialization,
);

criterion_group!(
    p2_benchmarks,
    bench_header_allocation,
    bench_header_map_creation,
    bench_header_iteration,
);

criterion_group!(
    p3_benchmarks,
    bench_body_chunk_serialization,
    bench_body_chunk_deserialization,
    bench_protocol_metrics,
    bench_connection_affinity,
);

criterion_group!(
    integration_benchmarks,
    bench_full_request_path,
);

criterion_main!(
    p0_benchmarks,
    p1_benchmarks,
    p2_benchmarks,
    p3_benchmarks,
    integration_benchmarks,
);
