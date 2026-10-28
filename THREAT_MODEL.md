# SealArena: Threat Model & Security Architecture

This document defines the formal threat model, security boundaries, attacker capabilities, mitigations, non-goals, residual risks, and architectural roadmap for **SealArena**.

---

## 1. System Assets

| Asset ID | Asset Name | Sensitivity | Owner | Security Objective |
|---|---|---|---|---|
| **A-1** | Red Team Attack Payloads | High (pre-evaluation) | Red Runner | Pre-evaluation secrecy via Commit-Reveal; post-evaluation binding. |
| **A-2** | Blue Team Defense Rules & Weights | Confidential | Blue Runner | Kept encrypted in storage; decrypted strictly inside Arbiter guard memory; never disclosed to Red. |
| **A-3** | Model KV-Cache & Internal State | Confidential | LLM Target | Session-isolated memory; cache salt per session; zero inter-tenant bleed. |
| **A-4** | System Prompt & Defense Canaries | Secret | Arbiter / Model | Canary tokens embedded in system prompt and rules; exfiltration prohibited. |
| **A-5** | Audit Ledger & Safety Records | Tamper-Evident | Security Auditor | Append-only SHA-256 hash chain; Ed25519 digital signatures; Merkle root checkpoints. |
| **A-6** | Tenant Resource Quotas | Availability | Sandbox Host | Cgroup quotas (CPU, memory, PIDs); fair queuing; DoS containment. |

---

## 2. Adversaries & Threat Actors

| Adversary Profile | Motivation | Capabilities |
|---|---|---|
| **Malicious Red Tenant (Attacker)** | Infer Blue team defense rules to construct undetectable jailbreaks; probe model cache for prior session data; exfiltrate system canaries; tamper with audit logs. | Arbitrary payload generation; timing measurements; container code execution; network scanning from inside `red-runner`. |
| **Curious Blue Tenant (Defender)** | Intercept Red attack payloads before evaluation to overfit defenses; gain access to Red's unpublished vulnerability research. | Rule deployment; aggregate telemetry inspection; container code execution inside `blue-runner`. |
| **Compromised Model Process** | Model subversion via prompt injection, hallucination, or adversarial suffixes. | Arbitrary text generation; attempts to emit system instructions or canaries. |
| **Noisy Neighbor / DoS Actor** | Exhaust compute/memory to disrupt competitor evaluation or starve broker availability. | Rapid concurrent requests; memory allocation spikes; fork-bombs. |

---

## 3. Trust Boundaries & Micro-Segmentation

```
[ Red Runner ]                 [ Blue Runner ]
(Tenant Domain)                (Tenant Domain)
      │                              │
══════╪══════════════════════════════╪═══════ [ TRUST BOUNDARY 1: Tenant Isolation ]
      │ (mTLS + red.crt)             │ (mTLS + blue.crt)
      ▼                              ▼
┌──────────────────────────────────────────┐
│             SEALARENA ARBITER            │ ◄─── [ TRUST BOUNDARY 2: Broker & Guard ]
│  - ABAC Token Validator (60s TTL)        │
│  - Guard Decryption Engine (AES-256-GCM) │
│  - Timing Padder (350ms Window)          │
│  - Canary Boundary Exfiltration Scanner  │
└────────────────────┬─────────────────────┘
                     │
═════════════════════╪═══════════════════════ [ TRUST BOUNDARY 3: Model & Admin Isolation ]
                     ├─────────────────────────┐
                     ▼                         ▼
            [ LLM Target ]            [ Audit Ledger ]
            (model-net)               (admin-net: Ed25519)
```

1. **Boundary 1 (Red vs. Blue)**: Red and Blue run in isolated Docker networks (`red-net` and `blue-net`). There is no IP route, bridge, or ARP table sharing between them.
2. **Boundary 2 (Tenant vs. Arbiter)**: Mutual TLS (mTLS) with client certificates; all requests must carry signed, scoped capability tokens.
3. **Boundary 3 (Arbiter vs. Model Target)**: Model Target resides on `model-net` and is unreachable by Red or Blue directly. Context is strictly salted and reset per session.
4. **Boundary 4 (Arbiter vs. Audit Ledger)**: Audit entries are cryptographically chained ($H_i = \text{SHA256}(H_{i-1} \parallel \dots)$) and signed with Ed25519.

---

## 4. What We Protect Against (In-Scope)

- **Direct Cross-Tenant Network Snooping**: Dropped by Docker internal network micro-segmentation and firewall rules.
- **DNS / Topology Enumeration**: Internal networks do not resolve foreign container hostnames.
- **Shared Filesystem / Process Snooping**: Non-root execution, `read_only: true` rootfs, isolated tmpfs, no shared volume mounts, independent PID namespaces.
- **Docker Daemon Breakout**: Zero `/var/run/docker.sock` exposure, `cap_drop: [ALL]`, `no-new-privileges: true`, custom seccomp profile blocking `ptrace`, `bpf`, `mount`.
- **Timing Side-Channel Exploits**: Fixed-time padding to 350ms window with Gaussian jitter ($\sigma = 4\text{ms}$), reducing attacker classifier accuracy from 100% to chance (~53%).
- **Prompt Injection & Canary Exfiltration**: Outbound response scanner intercepts and quarantines any response containing system or rule canaries.
- **Cross-Session KV-Cache Bleed**: Per-session context salting and memory clearing ensures Session B has 0% access to Session A context.
- **Audit Log Tampering / Forgery**: Hash chain continuity checks and Ed25519 digital signature validation immediately detect any byte-level log modification.
- **Resource Exhaustion**: Cgroup limits (`cpus: 0.50`, `memory: 256M`, `pids: 50`) prevent fork-bombs and contain blast radiuses.

---

## 5. What We Do NOT Protect Against (Out-of-Scope / Non-Goals)

To maintain systems and security engineering integrity, SealArena explicitly documents non-goals for this Docker-based proof-of-concept:
- **Malicious Host Root / Cloud Hypervisor Operator**: A root user on the host VM can dump memory or alter kernel state. (Requires Confidential Computing hardware like AMD SEV-SNP / Intel SGX).
- **Kernel 0-Day Local Privilege Escalations**: In standard runc mode, containers share the host Linux kernel. (Mitigated when run with `runtime: runsc` / gVisor).
- **Microarchitectural Hardware Side Channels**: Spectre, Meltdown, MDS, or power-analysis attacks on shared physical CPU cores.
- **Theoretical Infinite-Compute Quantum Adversaries**: Ed25519 and SHA-256 are classical cryptographic standards.

---

## 6. Conditions Where Guarantees Fail

| Guarantee | Failure Condition | Impact |
|---|---|---|
| **Network Micro-segmentation** | Misconfiguration assigning Red and Blue to a shared Docker bridge network. | Red could probe Blue TCP ports. |
| **Timing Normalization** | Target latency configured lower than model inference p99. | Slow model inferences exceed window, re-introducing tail latency timing leaks. |
| **Canary Exfiltration Protection** | Canary transformed via multi-step base64, ROT13, or acrostic ciphers unhandled by scanner regexes. | Partial canary pattern might bypass literal string matching. |
| **Commit-Reveal Binding** | Red fails to reveal salt before round timeout. | Round is marked forfeited / unverified on ledger. |

---

## 7. Residual Risk Matrix

| Risk ID | Risk Description | Likelihood | Impact | Severity | Current Mitigation | Planned Roadmap Solution |
|---|---|---|---|---|---|---|
| **R-1** | Kernel 0-day Container Escape | Low | Critical | **High** | Seccomp blocklist (`ptrace`, `bpf`), `cap_drop: ALL`, non-root user. | MicroVM isolation (Firecracker) or gVisor (`runsc`). |
| **R-2** | Cipher-Encoded Canary Leakage | Medium | Medium | **Medium** | Exact match + normalized regex scanning in Arbiter. | LLM-based boundary guard judge & entropy scanner. |
| **R-3** | CPU Microarchitectural Side Channels | Low | High | **Medium** | Fixed-time padding with random jitter. | Core pinning (vCPU pinning) and cache partitioning (CAT). |
| **R-4** | Arbiter Memory Scraping by Host Admin | Low | Critical | **High** | Guard memory zeroing on unload. | Confidential Enclaves (AMD SEV-SNP / AWS Nitro Enclaves). |

---

## 8. Architectural Roadmap

1. **Hardware Enclaves (AMD SEV-SNP / Intel SGX / AWS Nitro Enclaves)**:
   - Run the Arbiter Guard stage inside a hardware enclave with Remote Attestation. Cryptographic proofs verify that only genuine Blue rules execute without operator snooping.
2. **MicroVM Sandboxes (AWS Firecracker)**:
   - Replace container runtimes with lightweight microVMs providing independent guest Linux kernels for Red and Blue runners.
3. **eBPF Kernel Enforcement (Cilium / Tetragon)**:
   - Hardware-level and socket-level eBPF probes enforcing network packet drops and syscall monitoring directly in kernel space.
4. **Decentralized Transparency Logs (Sigstore / Rekor)**:
   - Publish Merkle root checkpoints to a public transparency log (e.g., Rekor) for verifiable third-party auditing.
