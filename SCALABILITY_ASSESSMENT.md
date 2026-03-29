# ELKIE Scalability Assessment — Multi-User SOC Readiness

## Executive Summary

ELKIE is architected as a **single-operator home lab SOC**. Running it as a multi-user SOC
would require significant changes across authentication, data isolation, processing
concurrency, and infrastructure. Below is a candid breakdown of what works, what doesn't,
and what to change.

**Current scalability grade: 2/10 for multi-user SOC use.**
**Effort to reach multi-user ready: Medium-Large (weeks, not months).**

---

## Current Architecture Strengths

| Area | What's Good |
|------|------------|
| **ELK foundation** | Elasticsearch is inherently horizontally scalable — good base choice |
| **Docker Compose** | Services are containerized, making replication feasible |
| **Authelia SSO** | Authentication gateway already exists — can be extended to RBAC |
| **Modular sentinels** | Each daemon is independent and follows a consistent pattern |
| **Env-driven config** | `.env.example` covers all tunables — good for multi-instance deploys |
| **Network isolation** | VLAN segmentation and ingest-only proxy are solid security foundations |

---

## Critical Scalability Gaps

### 1. Single-Node Elasticsearch (HIGH IMPACT)

```yaml
# deploy/docker-compose.yml
discovery.type: single-node
xpack.security.enabled: false
ES_JAVA_OPTS: -Xms2g -Xmx2g
```

**Problems:**
- Single node = single point of failure, no redundancy
- No authentication/authorization on ES — any container on the `elkie` network has full access
- 2GB heap is undersized for multi-user ingest volumes
- No index-level access control — all users see all data

**For multi-user SOC:**
- Deploy a 3-node ES cluster (minimum) with dedicated master/data/ingest roles
- Enable xpack security with API keys or native realm
- Implement index-level RBAC via ES roles (e.g., `analyst-readonly`, `admin-full`)
- Size heap to 50% of available RAM (up to 31GB per node)
- Add ILM policies for data retention tiers (hot/warm/cold)

### 2. No Multi-Tenancy or RBAC (HIGH IMPACT)

**Current state:** Authelia provides SSO but there's no concept of users, roles, or
permissions within ELKIE itself. Every authenticated user sees everything.

**What's needed:**
- User roles: `admin`, `analyst`, `viewer`
- Per-user or per-team alert subscriptions (currently one Discord webhook for all)
- Audit logging of analyst actions (who acknowledged what alert, when)
- Case/incident ownership and assignment
- SOC portal (`sessions.html`) is a static HTML page with client-side ES queries — no
  server-side access control

### 3. Sequential Sample Processing (HIGH IMPACT)

```
sample_analyzer.py — single-threaded poll loop
  → fetches sample → static analysis → dynamic analysis → LLM → MISP → report
  → 5-10 minutes per sample, blocks all other samples
```

**Problems:**
- One sample at a time. During a busy period (botnet dropping malware on 10 honeypots),
  the queue backs up with no visibility into backlog depth
- Single sandbox VM with snapshot restore between detonations — cannot parallelize
- REMnux is a single VM handling all static analysis
- Claude API calls are synchronous and rate-limited

**For multi-user SOC:**
- Add a task queue (Redis + Celery, or RabbitMQ) to decouple ingestion from analysis
- Run multiple sandbox VMs (Proxmox can clone templates) for parallel detonation
- Pool REMnux instances or containerize the static analysis toolchain
- Make LLM calls async with configurable concurrency limits
- Add a sample queue dashboard showing pending/in-progress/completed

### 4. File-Based State Persistence (MEDIUM IMPACT)

All sentinels persist state to local JSON files:
```
/home/legs/.sample_analyzer_state.json
/home/legs/.sentinel_state.json
/home/legs/.ml_sentinel_state.json
```

**Problems:**
- Not crash-safe (partial writes can corrupt state)
- Can't be shared across replicated instances
- No transactional guarantees

**For multi-user SOC:**
- Move state into Elasticsearch or Redis
- This enables running multiple instances of each sentinel for HA

### 5. SSH-Based Inter-Component Communication (MEDIUM IMPACT)

All sample transfers and analysis commands use direct SSH:
```python
subprocess.run(["ssh", "-J", jump_host, target, "cat", sample_path])
subprocess.run(["scp", "-o", f"ProxyJump={jump_host}", ...])
```

**Problems:**
- SSH connections are expensive to establish per-operation
- No connection pooling
- Hard to load-balance across multiple analysis VMs
- Credential management doesn't scale (SSH keys per instance)

**For multi-user SOC:**
- Consider an API layer on analysis VMs (FastAPI + file upload endpoint)
- Or use SSH connection multiplexing (`ControlMaster`) as a quick win
- Enables load balancing across a pool of analysis workers

### 6. Hardcoded Single-Instance Assumptions (MEDIUM IMPACT)

Many components assume they're the only instance:
- `sample_analyzer.py` polls ES without distributed locking — two instances would
  process the same sample twice
- Ghidra MCP server is a single HTTP endpoint on one VM
- Campaign clusterer and session correlator run as cron jobs with no coordination

**For multi-user SOC:**
- Add distributed locking (Redis `SETNX` or ES optimistic concurrency)
- Use leader election for singleton tasks (cron jobs)

### 7. SOC Portal Is a Static Page (MEDIUM IMPACT)

`soc-portal/sessions.html` is a single HTML file with inline JavaScript that queries
Elasticsearch directly from the browser.

**Problems:**
- No server-side API = no access control enforcement
- No backend means no place to implement case management, annotations, or workflows
- Can't enforce analyst-level permissions

**For multi-user SOC:**
- Build a backend API (FastAPI/Flask) that mediates all ES access
- Implement case management (assign, escalate, close incidents)
- Add WebSocket support for real-time alert feeds to multiple analysts
- Consider adopting an existing SOC platform (TheHive, DFIR-IRIS) for case management
  and integrate ELKIE as the detection/analysis engine

### 8. Alerting Is Broadcast-Only (LOW IMPACT)

All alerts go to a single Discord webhook. In a multi-user SOC:
- Different analysts need different alert feeds (by severity, by type, by assignment)
- Need on-call rotation support
- Need alert acknowledgment tracking
- Consider integration with PagerDuty/OpsGenie for escalation

### 9. No Horizontal Scaling for Grafana (LOW IMPACT)

Single Grafana instance with local volume storage. For multiple concurrent analysts:
- Dashboard load can be significant with 78 panels
- Consider Grafana with a PostgreSQL backend for HA
- Pre-render heavy dashboards or use snapshot caching

---

## Recommended Migration Path

### Phase 1: Foundation (Week 1-2)
1. **Enable ES security** — `xpack.security.enabled: true`, create roles/users
2. **Add a backend API** — FastAPI app that wraps ES queries with auth
3. **Move state to ES/Redis** — eliminate JSON file state
4. **SSH multiplexing** — `ControlMaster auto` in ssh_config for immediate throughput gain

### Phase 2: Concurrency (Week 3-4)
1. **Task queue** — Redis + Celery (or similar) for sample analysis pipeline
2. **Multiple sandbox VMs** — Proxmox VM templates, pool of 2-4 detonation VMs
3. **Distributed locking** — prevent duplicate processing across sentinel instances
4. **Containerize static analysis** — REMnux tools in Docker for horizontal scaling

### Phase 3: Multi-User Features (Week 5-6)
1. **RBAC in the SOC portal** — user roles, case assignment, audit trail
2. **Per-user alert routing** — severity-based subscriptions, on-call rotation
3. **Case management** — integrate TheHive or DFIR-IRIS alongside ELKIE
4. **ES cluster** — expand to 3+ nodes for redundancy and query performance

### Phase 4: Production Hardening (Week 7-8)
1. **Monitoring** — Prometheus + Grafana for ELKIE's own health (queue depth, processing latency, ES cluster health)
2. **Backup/DR** — ES snapshots to S3/NFS, state backup
3. **Rate limiting** — protect ES and API from runaway queries
4. **Load testing** — simulate 10+ concurrent analysts with realistic alert volumes

---

## Quick Wins (Do These Now)

| Change | Effort | Impact |
|--------|--------|--------|
| Enable `xpack.security` + basic auth | 1 hour | Prevents unauthorized ES access |
| SSH `ControlMaster` in ssh_config | 10 min | 2-3x faster sample transfers |
| Add `setup-ilm-policy.sh` to deployment | 30 min | Prevents index bloat over time |
| Move sentinel state to ES index | 2-3 hours | Crash-safe, shareable state |
| Add queue depth metric to Discord alerts | 1 hour | Visibility into processing backlog |

---

## Hardware Assessment

Your Dell R640 (96 cores, 128GB RAM) is actually well-suited for a small-team SOC
(3-5 analysts). The bottleneck is software architecture, not hardware. With the changes
above, this single server could handle:

- 3-node ES cluster (VMs) with 32GB heap each
- 4 parallel sandbox VMs for detonation
- 2 REMnux instances for static analysis
- Backend API + SOC portal
- All sentinel daemons with 2x redundancy

For 10+ analysts or high-volume environments (1000+ alerts/day), you'd want a second
physical server or cloud burst capacity.

---

## Summary

ELKIE's detection and analysis capabilities are impressive — the 10-step malware pipeline,
ML anomaly detection, and threat intel integration are well beyond most home labs. The
gap is in the **operational layer**: multi-user access control, concurrent processing,
and shared state management. The good news is that the modular sentinel architecture
and Docker-based deployment make these changes tractable without a full rewrite.
