# Product Requirements Document (PRD)
## Healthcare Consent & Audit Log

### 1. Overview & Objective

#### 1.1 Problem Statement
Patients often lack clear visibility and direct control over who accesses their medical records, while healthcare systems face challenges maintaining transparent, tamper-evident records of access permissions and data usage. Storing raw medical files directly on a blockchain is impractical due to privacy regulations (HIPAA, GDPR) and ledger data-size constraints.

#### 1.2 Product Vision
Build a **Healthcare Consent & Audit Log** prototype/model that gives patients explicit control to grant and revoke access permissions for healthcare providers while keeping actual medical files in an off-chain store, recording permission changes and read/write events on a blockchain for compliance auditing.

#### 1.3 Core Value Proposition
- **Patient Control (Consent):** Patients can grant or revoke access for specific providers or roles.
- **Privacy + Integrity Separation:** Sensitive medical files reside off-chain, while permission states and read/write events are recorded on-chain.
- **Accountability & Auditability:** Every permission change and read/write event is logged for auditing and compliance tracking.

---

### 2. Target Users & Roles

| Role | Responsibilities |
|---|---|
| **Patient** | Manages consent permissions (grant/revoke) for providers or roles and reviews the audit history of who accessed their records and when. |
| **Healthcare Provider** *(Doctor, Clinic, Lab)* | Requests access, views permitted medical records, and logs record reads or updates. |
| **Auditor / Compliance Viewer** *(Role-Based)* | Reviews audit log entries to verify access history and compliance against regulatory requirements. |

---

### 3. System Architecture

The system is structured into three core layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Layer 1: Presentation / Client                    │
│   • Patient Portal: Grant / revoke permissions & view audit trail     │
│   • Provider Portal: Request access, read / update clinical records    │
│   • Auditor Console: Chronological access inspection & compliance view│
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 Layer 2: Smart Contract / Ledger Logic                 │
│   • Consent State Enforcement: (PatientID, ProviderID/Role) -> State  │
│   • Access Control Gate: Verifies active grant before read/write       │
│   • Immutable Audit Ledger: Append-only cryptographic event logs       │
└──────────────────┬───────────────────────────────────┬─────────────────┘
                   │                                   │
                   │ Verifies                          │ Hashes &
                   │ Permissions                       │ Anchors Events
                   ▼                                   ▼
┌───────────────────────────────────────┐ ┌──────────────────────────────┐
│  Layer 3A: Off-Chain Medical Store    │ │  Layer 3B: Cryptographic     │
│  • Electronic Health Records (JSON/PDF│ │            Integrity         │
│  • Decoupled from public ledger       │ │  • SHA-256 Record Hashes     │
│  • Referenced via secure record IDs   │ │  • Zero-Knowledge / Proofs   │
└───────────────────────────────────────┘ └──────────────────────────────┘
```

1. **Patient & Provider Interfaces (Web/Mobile UI or Simulation Client):**
   - *Patient View:* Grant/revoke access to specific providers or roles and inspect the audit trail.
   - *Provider View:* Request access, view permitted records, and log record reads/writes.
2. **Smart Contract / Ledger Logic Layer:**
   - Enforces role-based permissions and consent states (*granted* vs. *revoked*).
   - Records immutable log entries whenever permissions change or records are read/written.
3. **Off-Chain Medical Data Store:**
   - Stores actual medical records/files outside the blockchain.
   - Supports linking via record pointers/identifiers and hash verification to check integrity of off-chain records against recorded metadata/hashes.

---

### 4. Functional Requirements & Core Workflows

#### 4.1 Granting Access
- **Trigger:** A patient selects a healthcare provider or role and grants permission.
- **System Behavior:**
  1. Smart contract updates the consent state for the `(patientId, providerId/role)` pair to `granted`.
  2. Smart contract records a `GRANT` event on-chain with timestamp and actor ID.

#### 4.2 Reading or Updating a Medical Record
- **Trigger:** A provider requests to read or update a patient's medical record.
- **System Behavior:**
  1. System verifies whether consent is currently active (`granted`) under smart contract rules.
  2. If unauthorized, access is denied and an unauthorized attempt event is optionally flagged.
  3. If authorized, the off-chain record is accessed/updated (and cryptographically verified against its hash/reference).
  4. A `READ` or `WRITE` event is logged on-chain for the audit trail.

#### 4.3 Revoking Access
- **Trigger:** A patient revokes a previously granted permission.
- **System Behavior:**
  1. Smart contract updates the consent state for the patient–provider pair to `revoked`.
  2. Smart contract records a `REVOKE` event on-chain.
  3. Subsequent read/write attempts by that provider are immediately rejected.

#### 4.4 Audit Trail Inspection
- **Trigger:** A patient or authorized viewer inspects access history.
- **System Behavior:**
  1. Displays chronological audit log entries showing `event type`, `actor ID`, `patient ID`, `record reference/hash`, and `timestamp`.
  2. Provides filter and verification capabilities for compliance auditors.

---

### 5. Data Model

#### 5.1 Identities & Roles
- **Attributes:** User/actor identifier, role definition (`patient`, `doctor`, `lab`, `clinic`, `auditor`).

#### 5.2 Consent / Permission State
- **Key:** `(patientId, providerId/role)`
- **Value / State:** `granted` or `revoked` (extensible to include scope, expiration timestamp).

#### 5.3 Audit Log Entry
- **Event Type:** `GRANT`, `REVOKE`, `READ`, `WRITE`
- **Actor ID:** Identifier of the user/provider performing the action
- **Patient ID:** Identifier of the patient whose consent or record is involved
- **Record Reference / Hash:** Pointer/identifier to the off-chain medical record and/or integrity hash
- **Timestamp:** ISO 8601 or block timestamp when the event occurred
- **Block / Tx Hash:** Cryptographic proof of audit entry immutability

#### 5.4 Off-Chain Record Reference
- Pointer/identifier linking the on-chain metadata/audit log to the medical file stored off-chain.

---

### 6. Phased Build Roadmap

- **Phase 1 — Rules & State Definitions:** Define user roles, consent state transitions (grant / revoke), and audit event types (read / write).
- **Phase 2 — Smart Contract / Ledger Logic:** Implement permission enforcement checks and append-only audit event logging.
- **Phase 3 — Off-Chain Storage Mock:** Set up an off-chain store (sample medical records / JSON files) linked via IDs/hashes.
- **Phase 4 — UI or Simulation & Testing:** Build a simple interface or simulation script to test granting access, reading records, revoking access, and verifying the audit log.
