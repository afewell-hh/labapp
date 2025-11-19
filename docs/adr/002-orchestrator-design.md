# ADR-002: Orchestrator Design

**Status:** Accepted
**Date:** 2025-11-04
**Deciders:** Project Lead, Engineering Team
**Technical Story:** Issue #7

## Context

The Hedgehog Lab Appliance requires a robust initialization system to manage the complex startup process involving multiple services and components. The orchestrator must:

1. **Handle Two Build Types:** Standard builds require full initialization (15-20 min), while pre-warmed builds only need to start services (2-3 min)
2. **Manage Complex Dependencies:** Services must start in the correct order (k3d → VLAB → GitOps → Observability)
3. **Provide User Feedback:** Users need visibility into initialization progress and status
4. **Be Reliable:** Handle failures gracefully with proper error handling and recovery
5. **Be Maintainable:** Clear architecture that other developers can extend and modify

The orchestrator runs as a systemd oneshot service on first boot and must be idempotent, resumable, and safe for concurrent execution prevention.

## Decision

Implement a **modular, state-driven orchestrator** with clear separation of concerns.

### Architecture Overview

The orchestrator follows a **plugin-based architecture** where each initialization task is a self-contained module with standardized interfaces.

**Core Principles:**
- **Modularity:** Each component (k3d, VLAB, GitOps, etc.) is a separate module
- **State Management:** Track progress to enable resume capability
- **Dependency Ordering:** Explicit dependency graph ensures correct startup sequence
- **Observability:** Comprehensive logging and progress reporting
- **Idempotency:** Safe to run multiple times without side effects

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Core                        │
│                                                             │
│  ┌───────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │ State Manager │  │ Module       │  │ Progress        │ │
│  │               │  │ Registry     │  │ Reporter        │ │
│  └───────────────┘  └──────────────┘  └─────────────────┘ │
│                                                             │
│  ┌───────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │ Dependency    │  │ Error        │  │ Lock            │ │
│  │ Resolver      │  │ Handler      │  │ Manager         │ │
│  └───────────────┘  └──────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ orchestrates
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Initialization Modules                    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Network      │  │ k3d          │  │ VLAB            │  │
│  │ Module       │  │ Module       │  │ Module          │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ GitOps       │  │ Observability│  │ Validation      │  │
│  │ Module       │  │ Module       │  │ Module          │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ uses
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Utility Layer                          │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Logger       │  │ Health       │  │ Retry           │  │
│  │              │  │ Checker      │  │ Handler         │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

#### 1. Orchestrator Core (`hedgehog-lab-orchestrator`)

**Responsibilities:**
- Load configuration and detect build type
- Initialize state management
- Acquire lock to prevent concurrent runs
- Load and validate modules
- Resolve dependencies and determine execution order
- Execute modules sequentially
- Report progress to user
- Handle errors and cleanup

**Implementation:** Main Bash script (`/usr/local/bin/hedgehog-lab-orchestrator`)

#### 2. State Manager

**Responsibilities:**
- Track module execution state (pending, running, completed, failed)
- Persist state to disk for resume capability
- Provide state query interface

**Storage:** `/var/lib/hedgehog-lab/state.json`

**State Format:**
```json
{
  "initialized": false,
  "build_type": "standard",
  "started_at": "2025-11-04T10:00:00Z",
  "modules": {
    "network": {"status": "completed", "completed_at": "2025-11-04T10:00:30Z"},
    "k3d": {"status": "running", "started_at": "2025-11-04T10:00:35Z"},
    "vlab": {"status": "pending"},
    "gitops": {"status": "pending"},
    "observability": {"status": "pending"}
  }
}
```

#### 3. Module Registry

**Responsibilities:**
- Register available modules
- Provide module metadata (dependencies, timeouts, etc.)
- Enable/disable modules based on build type

**Module Interface:**
Each module must implement:
- `run()`: Execute the initialization task
- `validate()`: Check if initialization was successful
- `cleanup()`: Rollback on failure (optional)
- `get_metadata()`: Return module metadata

**Module Metadata:**
```bash
MODULE_NAME="k3d"
MODULE_DESCRIPTION="Initialize k3d cluster"
MODULE_DEPENDENCIES=("network")
MODULE_TIMEOUT=600
MODULE_REQUIRED_FOR_STANDARD=true
MODULE_REQUIRED_FOR_PREWARMED=false
```

#### 4. Dependency Resolver

**Responsibilities:**
- Build dependency graph from module metadata
- Perform topological sort to determine execution order
- Detect circular dependencies
- Validate dependency requirements

**Algorithm:** Kahn's algorithm for topological sorting

#### 5. Progress Reporter

**Responsibilities:**
- Display initialization progress to user
- Show current module and estimated time remaining
- Provide real-time log streaming
- Display success/failure status

**Implementation Options:**
- Simple: Text-based progress with percentage
- Advanced: Terminal UI with progress bars (using `dialog` or similar)

**Output Locations:**
- Console: Real-time progress display
- Log file: `/var/log/hedgehog-lab/init.log`
- Systemd journal: `journalctl -u hedgehog-lab-init`

#### 6. Error Handler

**Responsibilities:**
- Catch and log errors
- Determine if error is retryable
- Execute retry logic with exponential backoff
- Trigger cleanup on fatal errors
- Record failure state for debugging

**Error Categories:**
- **Transient:** Network timeouts, temporary resource unavailability (retryable)
- **Configuration:** Invalid config, missing dependencies (not retryable)
- **Fatal:** System errors, critical failures (abort initialization)

#### 7. Lock Manager

**Responsibilities:**
- Prevent concurrent orchestrator runs
- Detect stale locks
- Clean up locks on exit

**Implementation:** File-based lock at `/var/lock/hedgehog-lab-init.lock`

### State Machine

The orchestrator follows this state machine for the overall initialization process:

```
                    ┌─────────┐
                    │  START  │
                    └────┬────┘
                         │
                         ▼
                ┌────────────────┐
                │  INITIALIZING  │
                │                │
                │ • Acquire lock │
                │ • Load state   │
                │ • Load modules │
                └────┬───────────┘
                     │
                     ▼
              ┌──────────────┐
              │  VALIDATING  │
              │              │
              │ • Check deps │
              │ • Validate   │
              └──┬───────────┘
                 │
                 ▼
          ┌──────────────────┐
          │  EXECUTING       │◄─────────┐
          │                  │          │
          │ • Run module     │          │
          │ • Update state   │          │
          │ • Validate       │          │
          └──┬───────────┬───┘          │
             │           │              │
             │ success   │ more modules │
             │           └──────────────┘
             ▼
      ┌─────────────┐
      │  FINALIZING │
      │             │
      │ • Cleanup   │
      │ • Set stamp │
      └──┬──────────┘
         │
         ▼
   ┌──────────┐
   │ COMPLETED│
   └──────────┘


   ERROR FLOW:
   ───────────
   Any error during execution:
        │
        ▼
   ┌──────────┐     retryable?
   │  ERROR   │─────────┬──────────┐
   └──────────┘         │          │
                        │ yes      │ no
                        │          │
                        ▼          ▼
                   ┌────────┐  ┌────────┐
                   │ RETRY  │  │ FAILED │
                   └───┬────┘  └────────┘
                       │
                       └──────► back to EXECUTING
```

### Module State Machine

Each module follows this state machine:

```
┌─────────┐
│ PENDING │
└────┬────┘
     │
     ▼
┌─────────┐
│ RUNNING │
└────┬────┘
     │
     ├──► ┌───────────┐
     │    │ COMPLETED │
     │    └───────────┘
     │
     ├──► ┌──────────┐
     │    │ RETRYING │──┐
     │    └──────────┘  │
     │         ▲        │
     │         └────────┘
     │
     └──► ┌────────┐
          │ FAILED │
          └────────┘
```

### File and Directory Structure

```
/
├── etc/
│   └── hedgehog-lab/
│       ├── build-type                          # "standard" or "prewarmed"
│       ├── orchestrator.conf                   # Main configuration
│       └── modules.d/                          # Module configurations
│           ├── 10-network.conf
│           ├── 20-k3d.conf
│           ├── 30-vlab.conf
│           ├── 40-gitops.conf
│           └── 50-observability.conf
│
├── usr/
│   └── local/
│       ├── bin/
│       │   ├── hedgehog-lab-orchestrator       # Main orchestrator script
│       │   └── hh-lab                          # CLI tool (future)
│       │
│       └── lib/
│           └── hedgehog-lab/
│               ├── orchestrator/
│               │   ├── core.sh                 # Core orchestrator functions
│               │   ├── state.sh                # State management
│               │   ├── logger.sh               # Logging utilities
│               │   ├── utils.sh                # Common utilities
│               │   └── modules.sh              # Module loading and execution
│               │
│               └── modules/                    # Initialization modules
│                   ├── 10-network.sh           # Network readiness check
│                   ├── 20-k3d.sh               # k3d cluster init
│                   ├── 30-vlab.sh              # VLAB initialization
│                   ├── 40-gitops.sh            # GitOps stack deployment
│                   ├── 50-observability.sh     # Observability stack
│                   └── 99-validation.sh        # Final validation
│
├── var/
│   ├── lib/
│   │   └── hedgehog-lab/
│   │       ├── initialized                     # Stamp file (empty when done)
│   │       ├── state.json                      # Current state
│   │       ├── modules/                        # Per-module state/data
│   │       │   ├── k3d/
│   │       │   ├── vlab/
│   │       │   └── gitops/
│   │       └── checkpoints/                    # Future: state snapshots
│   │
│   ├── log/
│   │   └── hedgehog-lab/
│   │       ├── init.log                        # Main orchestrator log
│   │       ├── modules/                        # Per-module logs
│   │       │   ├── network.log
│   │       │   ├── k3d.log
│   │       │   ├── vlab.log
│   │       │   ├── gitops.log
│   │       │   └── observability.log
│   │       └── errors/                         # Error dumps
│   │
│   └── lock/
│       └── hedgehog-lab-init.lock              # Initialization lock
│
└── lib/
    └── systemd/
        └── system/
            └── hedgehog-lab-init.service       # Systemd service unit
```

### Module Execution Order

**Standard Build:**
```
1. network        (wait for connectivity)
2. k3d            (create k3d-observability cluster)
3. vlab           (initialize Hedgehog VLAB - longest step)
4. gitops         (deploy ArgoCD, Gitea)
5. observability  (deploy Prometheus, Grafana, Loki)
6. validation     (verify all services healthy)
```

**Pre-warmed Build:**
```
1. network        (wait for connectivity)
2. k3d            (start existing cluster)
3. vlab           (start existing VLAB)
4. gitops         (verify services running)
5. observability  (verify services running)
6. validation     (verify all services healthy)
```

### Configuration Format

**Main Configuration (`/etc/hedgehog-lab/orchestrator.conf`):**
```bash
# Hedgehog Lab Orchestrator Configuration

# Build type (set during image build)
BUILD_TYPE="standard"

# Timeouts (seconds)
GLOBAL_TIMEOUT=2400           # 40 minutes max
NETWORK_TIMEOUT=300           # 5 minutes
MODULE_DEFAULT_TIMEOUT=600    # 10 minutes per module

# Retry configuration
MAX_RETRIES=3
RETRY_BACKOFF_BASE=5          # Exponential backoff base (seconds)

# Logging
LOG_LEVEL="INFO"              # DEBUG, INFO, WARN, ERROR
LOG_RETENTION_DAYS=30

# Progress reporting
SHOW_PROGRESS_BAR=true
PROGRESS_UPDATE_INTERVAL=5    # seconds

# Paths
STATE_DIR="/var/lib/hedgehog-lab"
LOG_DIR="/var/log/hedgehog-lab"
MODULE_DIR="/usr/local/lib/hedgehog-lab/modules"
```

**Module Configuration Example (`/etc/hedgehog-lab/modules.d/30-vlab.conf`):**
```bash
# VLAB Initialization Module Configuration

# Module metadata
MODULE_NAME="vlab"
MODULE_DESCRIPTION="Initialize Hedgehog Virtual Lab"
MODULE_DEPENDENCIES="network k3d"
MODULE_TIMEOUT=1200           # 20 minutes (longest module)

# Module-specific settings
VLAB_TOPOLOGY="7switch"
VLAB_WAIT_TIMEOUT=600
VLAB_HEALTH_CHECK_INTERVAL=10

# Build type behavior
STANDARD_ACTION="initialize"  # Full initialization
PREWARMED_ACTION="start"      # Just start services
```

## Consequences

### Positive

- **Modularity:** Easy to add new initialization tasks without modifying core orchestrator
- **Maintainability:** Clear separation of concerns, well-defined interfaces
- **Debuggability:** Comprehensive logging and state tracking
- **Reliability:** Proper error handling, retry logic, and state management
- **Testability:** Individual modules can be tested in isolation
- **Extensibility:** Plugin architecture allows community contributions
- **User Experience:** Clear progress feedback and error messages

### Negative

- **Complexity:** More complex than a simple linear script
- **Development Time:** Requires more upfront design and implementation
- **Learning Curve:** New contributors need to understand the architecture
- **File Count:** Multiple files vs. single monolithic script

### Neutral

- **Performance:** Slightly more overhead than monolithic script, but negligible
- **Disk Usage:** Additional files and state tracking (~1-2 MB)

## Implementation Notes

### Phase 1: MVP (Issue #8)
- Implement core orchestrator with basic module support
- Create simple text-based progress reporting
- Implement essential modules (network, k3d, vlab, gitops, observability)
- Basic state management and error handling

### Phase 2: Enhancement (Future)
- Advanced terminal UI with progress bars
- Resume capability for failed initializations
- Parallel module execution where dependencies allow
- Health monitoring and auto-recovery
- Web-based progress dashboard

### Technology Choices

**Language:** Bash
- **Rationale:** Already used in provisioning scripts, no runtime dependencies, native to Linux
- **Alternatives Considered:** Python (requires runtime), Go (requires compilation)

**State Storage:** JSON
- **Rationale:** Human-readable, easy to parse with `jq`, widely supported
- **Alternatives Considered:** SQLite (overkill), plain text (harder to parse)

**Logging:** Combined approach
- **Rationale:** Systemd journal for system integration, file logs for persistence
- **Format:** Structured logging with timestamps and log levels

### Security Considerations

- **Privilege:** Runs as root (required for system initialization)
- **Input Validation:** All module inputs validated before execution
- **Secrets:** No secrets in logs or state files (use secure storage)
- **Lock File:** Prevents race conditions and concurrent runs
- **Systemd Hardening:** `NoNewPrivileges=true`, `PrivateTmp=true` (the hhfab-vlab.service unit is exempt so it can run sudo helpers for TAP creation)

### Testing Strategy

**Unit Tests:**
- Test individual module functions
- Test state management operations
- Test dependency resolution algorithm

**Integration Tests:**
- Test complete initialization flow
- Test error handling and retry logic
- Test resume capability

**System Tests:**
- Test actual appliance boot in VM
- Verify all services start correctly
- Test both standard and pre-warmed builds

## Related Decisions

- ADR-001: Dual Build Pipeline Strategy
- ADR-003: Scenario Management System *(forthcoming)*
- ADR-004: Checkpoint System *(forthcoming)*

## References

- Issue #7: Design orchestrator architecture
- Issue #8: Implement orchestrator main script
- Packer scripts: `packer/scripts/hedgehog-lab-orchestrator`
- Systemd service: `packer/scripts/hedgehog-lab-init.service`
- Cloud-init patterns: https://cloudinit.readthedocs.io
- Systemd best practices: https://www.freedesktop.org/software/systemd/man/systemd.service.html

## Decision Rationale

This modular architecture balances complexity with maintainability. While it requires more upfront work than a simple script, it provides:

1. **Scalability:** Easy to add features like scenario switching, checkpoints, and auto-recovery
2. **Reliability:** Proper state management and error handling prevent partial initialization
3. **User Experience:** Clear progress feedback reduces user anxiety during 15-20 min initialization
4. **Community:** Plugin architecture enables community contributions without core changes

The plugin-based design is inspired by successful orchestration systems like cloud-init, systemd, and Kubernetes operators, adapted for our specific use case of appliance initialization.
