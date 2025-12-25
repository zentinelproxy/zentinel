# {{project-name}}

{{description}}

## Installation

### From crates.io (when published)

```bash
cargo install {{project-name}}
```

### From source

```bash
git clone https://github.com/YOUR_USERNAME/{{project-name}}
cd {{project-name}}
cargo build --release
```

## Usage

Run the agent:

```bash
{{project-name}} --socket /var/run/sentinel/{{project-name}}.sock
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_SOCKET` | Path to Unix socket | `/tmp/{{project-name}}.sock` |
| `AGENT_LOG_LEVEL` | Log level (trace, debug, info, warn, error) | `info` |

## Configuration in Sentinel

Add to your Sentinel proxy configuration:

```kdl
agents {
    agent "{{project-name}}" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/{{project-name}}.sock"
        }
        events ["request_headers"]
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "my-route" {
        matches { path-prefix "/" }
        upstream "backend"
        agents ["{{project-name}}"]
    }
}
```

## Development

### Running locally

```bash
# Terminal 1: Start the agent
AGENT_LOG_LEVEL=debug cargo run -- --socket /tmp/{{project-name}}.sock

# Terminal 2: Start Sentinel proxy with this agent configured
sentinel -c config.kdl
```

### Running tests

```bash
cargo test
```

## License

MIT OR Apache-2.0
