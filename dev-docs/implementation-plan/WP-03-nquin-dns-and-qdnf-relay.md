# WP-03 (P0/P1): QualiaDB `NQuin` DNS Server & Live QDNF Relay (`CSCP-08` & `CSCP-09`)

**Work Package ID:** `WP-03`  
**Priority:** `P0/P1`  
**Depends On:** None (can execute in parallel with `WP-01`/`WP-02`)  
**Target Repositories & Crates:**  
- `qualiaDB`: `crates/qualia-core-db/src/net/dns/`, `crates/qualia-core-db/src/net/qdnf/`, `crates/qualia-core-db/src/governance/web_civics.rs`, `crates/qualia-peer/`  
- `webizen-host`: `crates/webizen-host-dns/` (UDP/TCP `:53`, DoH, DoT, DoQ listeners & QDNF relay daemon)  

---

## 1. Objective & Problem Statement

Conventional DNS servers (BIND, Unbound, CoreDNS) parse variable-length text strings and chase pointers across heap-allocated radix trees on every query, treat ICANN DNS domains as the root of human identity, and lack semantic policy filtering. Furthermore, two key public-network milestones in the Qualia Decentralized Network Fabric (**`CSCP-08`** public Internet WSS/MASQUE bound-UDP relay and **`CSCP-09`** live two-host Internet trial on [`webizen.au/qdnf.html`](https://webizen.au/qdnf.html)) currently remain `false` solely because static GitHub Pages cannot host a live relay endpoint.

**WP-03** exposes `qualia-core-db`'s `net/dns/` 48-byte `NQuin` lookup ring as a high-speed authoritative and recursive DNS server (`:53`, DoH, DoT, DoQ) with in-flight deontic/SHACL policy filtering (`QPolicy`), dual-stack QDNF naming (`QLink`, `DNI`, `QRoute`, `QResolve`), and uses the live `webizen-host` VPS endpoint to qualify **`CSCP-08`** and **`CSCP-09`** on the public Internet.

---

## 2. Target Modules & Codebase Integration Map

| Subsystem | Authoritative File / Module in `qualiaDB` | Engineering Action Required |
|---|---|---|
| **48-Byte `NQuin` DNS Engine** | `crates/qualia-core-db/src/net/dns/` (wire codec, resolver, cache ring, quin records, ontology, SDN, lossless archive) | Bind `net/dns/` to live UDP/TCP `:53`, DoH (`:443/dns-query`), DoT (`:853`), and DoQ (`:853` QUIC) listeners with optional Linux `AF_XDP` / `eBPF` packet bypass. |
| **In-Flight Deontic DNS Firewall (`QPolicy`)** | `crates/qualia-core-db/src/net/qdnf/policy_labels/`, `deontic_logic.rs`, `net/qdnf/profiles/` | Evaluate deontic rules (`0x10–0x12`) and IFC policy labels in-flight inside the 42 MiB `SlgArena` for split-horizon consent gating and jurisdiction-aware routing (`jurisdiction.n3`). |
| **Bitemporal Lossless DNS Archive** | `crates/qualia-core-db/src/net/dns/` (lossless archive), `q42/journal.rs` | Record every DNS zone change and DNSSEC/DANE rollover into an append-only `.q42j` journal with `lifecycle:validFrom` and `lifecycle:transactionFrom`. |
| **QDNF Honeycomb & `CSCP-08`/`09` Relay** | `crates/qualia-core-db/src/net/qdnf/`, `governance/web_civics.rs`, `crates/qualia-peer/` | Run `PeerHost` public WSS, HTTP/2 Extended CONNECT, MASQUE bound-UDP relay (`CSCP-08`), and two-host live Internet verification (`CSCP-09`). |

---

## 3. Step-by-Step Implementation Tasks

### Task 3.1: $O(1)$ `q_hash()` 48-Byte `NQuin` DNS Server (`HotZeroHeap`)
1. Compile authoritative zone records (`A`, `AAAA`, `CNAME`, `TXT`, `SRV`, `HTTPS`, `SVCB`, `DNSKEY`, `RRSIG`, `TLSA`, plus `_did` and `Q42` records) into a pre-allocated, cache-line-aligned `HotZeroHeap` `NQuin` ring buffer (`net/dns/`):
   - `subject`: 64-bit FNV-1a `q_hash()` of normalized domain label + RRType bits.
   - `predicate`: Record class/type + QDNF routing lane + `DEFEATER_BIT` policy flags.
   - `object`: Inline packed IPv4/IPv6 address, DANE TLSA digest, or `did:q42` (`MSB = 1`) lexicon pointer to `Q42LEX v4` for multi-string `TXT` / `HTTPS` records.
   - `context`: Authoritative zone DID hash + sensitivity class (`PUBLIC=0`, `RESTRICTED=1`, `CLASSIFIED=2`).
   - `metadata`: `PermissiveRoutingLane` (`[61..62]`), Lamport logical clock (`[32..60]`), and TTL expiry epoch (`[0..31]`).
2. Expose listeners for:
   - **Legacy UDP/TCP `:53`** with automatic DNSSEC signing (Ed25519 / ECDSA P-256) and DANE TLSA synthesis.
   - **Encrypted DNS**: DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ) authenticated with `WebizenID-TLS` or ACME certificates.
   - **Automatic Discovery Synthesis**: Automatically serve `_did.<domain>` `TXT` records, `HTTPS`/`SVCB` records advertising QPR/HTTP3 endpoints, and `.well-known/did.json` + `.well-known/qdnf` descriptors.

### Task 3.2: In-Flight Deontic & SHACL Policy Firewall (`QPolicy`) & Bitemporal Archive
1. Wire `QPolicy` evaluation in `net/dns/` before emitting any DNS response packet:
   - **Consent-Gated Split-Horizon DNS**: Records with `context` sensitivity `RESTRICTED` or `CLASSIFIED` (e.g., private family device endpoints or paired `mylaptop.mydomain.tld` relays) resolve **only** when the query carries a valid `DNI` cookie, TSIG, or `WebizenID-TLS` DoH/DoQ session proof; unauthenticated scanners receive `NXDOMAIN`.
   - **Jurisdiction-Aware Routing (`jurisdiction.n3` + `net/qdnf/profiles/` E16.1–E16.7)**: Evaluate deontic `OP_FORBID` (`0x12`) rules to block known malicious telemetry endpoints and steer relay answers away from non-compliant jurisdictions.
2. Journal all zone mutations and DNSSEC/DANE key rollovers into `.q42j` using bitemporal predicates (`lifecycle:validFrom`, `lifecycle:transactionFrom`), preserving an unbroken evidentiary chain of domain stewardship.

### Task 3.3: Dual-Stack QDNF Integration & Live `CSCP-08` / `CSCP-09` Qualification
1. Wire the six-layer QDNF Honeycomb stack on the VPS host:
   - **`QLink` & `DNI`**: Cryptographic neighbour adjacency proofs and expiring topological locators (`DNI`) so network paths never leak permanent human identifiers.
   - **`QRoute` & Cryptokey IPv6 (`governance/web_civics.rs`)**: Constraint-first routing (`validate → index → plan` in `net/qdnf/route/`) with deterministic **Ed25519 → ULA IPv6 (`fd00::/8`) derivation** over `SocialWebNet` (userspace WireGuard) and CSCP transition bearers.
   - **`QResolve` (`net/qdnf/resolve/qsr`)**: Direct peer-to-peer resolution of `did:qi`, `did:q42`, and content-addressed `.q42`/`.hmc` digests independent of ICANN DNS.
2. Execute the **Live Two-Host Public Internet Qualification (`CSCP-08` & `CSCP-09`)**:
   - Deploy `webizen-host` on a live public Linux VPS hostname alongside a second remote host / local `webizen-desktop` peer.
   - Run the end-to-end `CSCP-08` (public Internet WSS + MASQUE bound-UDP relay) and `CSCP-09` (two-host mutual handshake, mailbox lease, and receipt verification) test suite, capture the signed cryptographic evidence receipts, and update the honesty matrix flags in `qualiaDB` (`webizen.au/qdnf.html`).

---

## 4. Verification & Exit Evidence

- [ ] **Zero-Heap $O(1)$ DNS Benchmark**: `assert_zero_alloc` test confirms `net/dns/` resolves `A`, `AAAA`, `HTTPS`, `TXT`, and `_did` queries in $O(1)$ constant time with zero heap allocations.
- [ ] **Split-Horizon `QPolicy` Test**: Unauthenticated query for a `RESTRICTED` family/device subdomain receives `NXDOMAIN`; query with a valid `DNI` cookie or `WebizenID-TLS` session receives the private ULA IPv6 / endpoint record.
- [ ] **`CSCP-08` & `CSCP-09` Public Internet Receipts**: Live two-host trial completes over the public Internet; `CSCP-08` and `CSCP-09` evidence flags flip from `false` to verified in-tree with committed receipt artifacts.
