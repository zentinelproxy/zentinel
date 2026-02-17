# Issue Labels

Zentinel uses a structured labeling system for issue triage and organization.

## Label Categories

### Type (`type:*`)

What kind of issue is this?

| Label | Description | Color |
|-------|-------------|-------|
| `type:bug` | Something isn't working correctly | `#d73a4a` |
| `type:feature` | New functionality request | `#a2eeef` |
| `type:enhancement` | Improvement to existing functionality | `#7057ff` |
| `type:docs` | Documentation only | `#0075ca` |
| `type:refactor` | Code improvement without behavior change | `#fef2c0` |
| `type:performance` | Performance improvement | `#f9d0c4` |
| `type:security` | Security-related issue | `#b60205` |

### Area (`area:*`)

Which part of the codebase is affected?

| Label | Description | Color |
|-------|-------------|-------|
| `area:proxy` | Core proxy (`zentinel-proxy`) | `#1d76db` |
| `area:config` | Configuration (`zentinel-config`) | `#1d76db` |
| `area:agent-protocol` | Agent protocol (`zentinel-agent-protocol`) | `#1d76db` |
| `area:common` | Shared utilities (`zentinel-common`) | `#1d76db` |
| `area:wasm` | WASM runtime | `#1d76db` |
| `area:agents` | External agents (not protocol) | `#1d76db` |
| `area:ci` | CI/CD and workflows | `#1d76db` |
| `area:docker` | Docker and containers | `#1d76db` |

### Scope (`scope:*`)

Which functional area?

| Label | Description | Color |
|-------|-------------|-------|
| `scope:routing` | Request routing and matching | `#c5def5` |
| `scope:upstream` | Upstream selection and health | `#c5def5` |
| `scope:rate-limit` | Rate limiting | `#c5def5` |
| `scope:tls` | TLS/SSL handling | `#c5def5` |
| `scope:caching` | Response caching | `#c5def5` |
| `scope:observability` | Metrics, logs, traces | `#c5def5` |
| `scope:kdl` | KDL configuration syntax | `#c5def5` |

### Priority (`priority:*`)

How urgent is this?

| Label | Description | Color |
|-------|-------------|-------|
| `priority:critical` | Production down, security vulnerability | `#b60205` |
| `priority:high` | Major functionality broken | `#d93f0b` |
| `priority:medium` | Important but not urgent | `#fbca04` |
| `priority:low` | Nice to have, minor issue | `#0e8a16` |

### Status (`status:*`)

What's the current state?

| Label | Description | Color |
|-------|-------------|-------|
| `status:triage` | Needs initial review | `#ededed` |
| `status:confirmed` | Verified, ready for work | `#0e8a16` |
| `status:blocked` | Waiting on external factor | `#d93f0b` |
| `status:needs-info` | Waiting for reporter response | `#fbca04` |
| `status:wontfix` | Declined, not aligned with goals | `#ffffff` |
| `status:duplicate` | Already reported | `#cfd3d7` |

### Manifesto (`manifesto:*`)

Alignment with Zentinel's principles (for features/enhancements).

| Label | Description | Color |
|-------|-------------|-------|
| `manifesto:bounded` | Has clear resource limits | `#d4c5f9` |
| `manifesto:observable` | Properly instrumented | `#d4c5f9` |
| `manifesto:explicit` | No hidden behavior | `#d4c5f9` |
| `manifesto:review-needed` | Needs Manifesto alignment review | `#ff9f1c` |

### Effort (`effort:*`)

Estimated complexity (for planning).

| Label | Description | Color |
|-------|-------------|-------|
| `effort:small` | < 1 day, isolated change | `#c2e0c6` |
| `effort:medium` | 1-3 days, multiple files | `#fef2c0` |
| `effort:large` | 3+ days, architectural impact | `#f9d0c4` |

### Special

| Label | Description | Color |
|-------|-------------|-------|
| `good-first-issue` | Good for newcomers | `#7057ff` |
| `help-wanted` | Community contributions welcome | `#008672` |
| `breaking-change` | Will require major version bump | `#b60205` |
| `dependencies` | Dependency updates | `#0366d6` |

---

## Label Combinations

### Bug Triage Flow

```
New bug → type:bug + status:triage
  ↓
Confirmed → + status:confirmed + priority:* + area:*
  ↓
In progress → (assign)
  ↓
Resolved → (close)
```

### Feature Request Flow

```
New feature → type:feature + status:triage
  ↓
Review → + manifesto:review-needed
  ↓
Approved → + status:confirmed + area:* + effort:*
  ↓
Declined → + status:wontfix (close with explanation)
```

### Example Combinations

| Issue | Labels |
|-------|--------|
| Agent pool memory leak | `type:bug` `area:agent-protocol` `scope:upstream` `priority:high` |
| Add gRPC health checks | `type:feature` `area:agent-protocol` `effort:medium` `manifesto:observable` |
| Improve error message for invalid KDL | `type:enhancement` `area:config` `scope:kdl` `effort:small` `good-first-issue` |
| Security: TLS downgrade possible | `type:security` `area:proxy` `scope:tls` `priority:critical` |

---

## Creating Labels

Run this script to create all labels:

```bash
# Type labels
gh label create "type:bug" --color "d73a4a" --description "Something isn't working correctly"
gh label create "type:feature" --color "a2eeef" --description "New functionality request"
gh label create "type:enhancement" --color "7057ff" --description "Improvement to existing functionality"
gh label create "type:docs" --color "0075ca" --description "Documentation only"
gh label create "type:refactor" --color "fef2c0" --description "Code improvement without behavior change"
gh label create "type:performance" --color "f9d0c4" --description "Performance improvement"
gh label create "type:security" --color "b60205" --description "Security-related issue"

# Area labels
gh label create "area:proxy" --color "1d76db" --description "Core proxy (zentinel-proxy)"
gh label create "area:config" --color "1d76db" --description "Configuration (zentinel-config)"
gh label create "area:agent-protocol" --color "1d76db" --description "Agent protocol (zentinel-agent-protocol)"
gh label create "area:common" --color "1d76db" --description "Shared utilities (zentinel-common)"
gh label create "area:wasm" --color "1d76db" --description "WASM runtime"
gh label create "area:agents" --color "1d76db" --description "External agents (not protocol)"
gh label create "area:ci" --color "1d76db" --description "CI/CD and workflows"
gh label create "area:docker" --color "1d76db" --description "Docker and containers"

# Scope labels
gh label create "scope:routing" --color "c5def5" --description "Request routing and matching"
gh label create "scope:upstream" --color "c5def5" --description "Upstream selection and health"
gh label create "scope:rate-limit" --color "c5def5" --description "Rate limiting"
gh label create "scope:tls" --color "c5def5" --description "TLS/SSL handling"
gh label create "scope:caching" --color "c5def5" --description "Response caching"
gh label create "scope:observability" --color "c5def5" --description "Metrics, logs, traces"
gh label create "scope:kdl" --color "c5def5" --description "KDL configuration syntax"

# Priority labels
gh label create "priority:critical" --color "b60205" --description "Production down, security vulnerability"
gh label create "priority:high" --color "d93f0b" --description "Major functionality broken"
gh label create "priority:medium" --color "fbca04" --description "Important but not urgent"
gh label create "priority:low" --color "0e8a16" --description "Nice to have, minor issue"

# Status labels
gh label create "status:triage" --color "ededed" --description "Needs initial review"
gh label create "status:confirmed" --color "0e8a16" --description "Verified, ready for work"
gh label create "status:blocked" --color "d93f0b" --description "Waiting on external factor"
gh label create "status:needs-info" --color "fbca04" --description "Waiting for reporter response"
gh label create "status:wontfix" --color "ffffff" --description "Declined, not aligned with goals"
gh label create "status:duplicate" --color "cfd3d7" --description "Already reported"

# Manifesto labels
gh label create "manifesto:bounded" --color "d4c5f9" --description "Has clear resource limits"
gh label create "manifesto:observable" --color "d4c5f9" --description "Properly instrumented"
gh label create "manifesto:explicit" --color "d4c5f9" --description "No hidden behavior"
gh label create "manifesto:review-needed" --color "ff9f1c" --description "Needs Manifesto alignment review"

# Effort labels
gh label create "effort:small" --color "c2e0c6" --description "< 1 day, isolated change"
gh label create "effort:medium" --color "fef2c0" --description "1-3 days, multiple files"
gh label create "effort:large" --color "f9d0c4" --description "3+ days, architectural impact"

# Special labels
gh label create "good-first-issue" --color "7057ff" --description "Good for newcomers"
gh label create "help-wanted" --color "008672" --description "Community contributions welcome"
gh label create "breaking-change" --color "b60205" --description "Will require major version bump"
gh label create "dependencies" --color "0366d6" --description "Dependency updates"
```
