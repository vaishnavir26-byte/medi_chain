# Healthcare Consent & Audit Log (MediChain Consent)

**Version:** 1.0.0  
**Compliance Standards:** HIPAA Security Rule (45 CFR § 164.312(b) Audit Controls), GDPR (Article 7 Conditions for Consent)  
**Architecture:** Cryptographic Append-Only Blockchain Ledger + Decoupled Off-Chain Medical Document Store + Responsive Multi-Persona Web Dashboard  

---

## 1. Executive Summary & Problem Solved

Modern healthcare architectures face two conflicting mandates:
1. **Patient Data Privacy & Regulatory Compliance:** Storing raw protected health information (PHI) directly on a public or permissioned blockchain violates regulatory data privacy rules (e.g., GDPR's "Right to be Forgotten", HIPAA privacy rules) and imposes severe block size and throughput bottlenecks.
2. **Accountability & Integrity Verification:** Traditional centralized databases permit undetected database administrator edits, silent record tampering, and lack verifiable, non-repudiable audit logs of when healthcare providers access sensitive clinical files.

**MediChain Consent** resolves this dichotomy by establishing a decoupled **On-Chain / Off-Chain Architecture**:
- **Sensitive Clinical Records Reside Off-Chain:** Patient Electronic Health Records (EHR), laboratory panels, prescription regimens, and diagnostic radiology scans are stored exclusively in an off-chain data store.
- **Consent States & Audit Events Reside On-Chain:** Patient consent grants/revocations, access checks, and cryptographic SHA-256 integrity digests are immutably sealed into an append-only blockchain ledger with recursive Merkle tree validation.

---

## 2. System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Layer 1: Presentation Layer                       │
│    Interactive Multi-Persona Web App (Tailwind CSS, Lucide Icons)      │
│    • Patient Portal (P-101 Alice Smith)                                │
│    • Provider Console (DOC-201 Dr. Carter, LAB-301 BioCore)            │
│    • Compliance Auditor Console (AUD-501 Evelyn Reed)                  │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ HTTP / REST / JSON
┌────────────────────────────────────▼───────────────────────────────────┐
│                 Layer 2: Application & API Dispatcher                  │
│    Python Server (`healthcare_consent/server.py`)                      │
│    Zero-dependency Threaded HTTP Engine, Session Identity Resolver     │
└──────────────────┬───────────────────────────────────┬─────────────────┘
                   │                                   │
                   │ Evaluates                         │ Records Events
                   ▼                                   ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│  Layer 3: Smart Contract Logic       │  │  Layer 4: Blockchain Ledger  │
│  `ConsentSmartContractEngine`        │  │  `BlockchainLedger`          │
│  • Grant / Revoke state transitions  │  │  • Append-only SHA-256 blocks│
│  • Time-bounded expiration check     │  │  • O(log N) Merkle Tree roots│
│  • Granular scope verification       │  │  • Full cryptographic chain  │
│  • Emergency Break-Glass override    │  │    validation from Genesis    │
└──────────────────┬───────────────────┘  └──────────────────────────────┘
                   │
                   │ Verifies Hashes &
                   │ Reads/Writes Document
                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Layer 5: Decoupled Off-Chain Storage                  │
│    `OffChainMedicalStore` (`healthcare_consent/storage/records/`)      │
│    • Electronic Health Records (EHR_GENERAL)                           │
│    • Laboratory & Diagnostic Blood Panels (LAB_REPORTS)                │
│    • Outpatient Prescription Regimens (PRESCRIPTIONS)                  │
│    • Diagnostic Imaging & Scans (IMAGING)                              │
│    • Real-time SHA-256 Integrity Verification & Tamper Detection       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Functional Workflows

### 3.1 Granting Consent (FR-4.1)
1. **Trigger:** Patient selects a healthcare provider (e.g. Dr. Sarah Carter or BioCore Labs), chooses an access scope (`ALL`, `EHR_GENERAL`, `LAB_REPORTS`, `PRESCRIPTIONS`, or `IMAGING`), and defines an expiration duration (e.g. 1 hour, 24 hours, 7 days, 30 days, or permanent).
2. **Smart Contract Evaluation:** The smart contract updates the consent state for `(patientId, providerId, scope)` to `granted` with an `expires_at` timestamp.
3. **On-Chain Audit Sealing:** A `GRANT` audit event is created, hashed, and immediately mined into a new block on the blockchain ledger.

### 3.2 Reading Records (FR-4.2)
1. **Trigger:** A healthcare provider requests to read a patient's medical record.
2. **Access Control Check:** The smart contract evaluates:
   - Does an active consent grant exist for `(patientId, providerId)` under either `Scope.ALL` or the specific record's category?
   - Has the consent expired?
3. **Branch A — Authorized Read:**
   - The off-chain document is retrieved from disk.
   - The live document's SHA-256 hash is computed and verified against the on-chain anchored hash.
   - A `READ` event is sealed into a new block on-chain.
4. **Branch B — Unauthorized Attempt:**
   - Access is immediately blocked (`403 Forbidden`).
   - An `UNAUTHORIZED_ATTEMPT` event with actor ID, target patient ID, and rejection reason is sealed into the blockchain for compliance tracking.
5. **Branch C — Emergency Break-Glass Override:**
   - In emergency trauma situations where the patient is unable to grant consent, an authorized physician can engage the Break-Glass override with a mandatory clinical justification.
   - The record is opened, but the `READ` event is flagged with `emergency_override: true` to trigger high-priority compliance audits.

### 3.3 Writing Records (FR-4.2)
1. **Trigger:** An authorized doctor or diagnostic laboratory submits an updated clinical note or new diagnostic panel.
2. **Access Control Check:** The smart contract verifies active consent for the corresponding scope.
3. **Off-Chain Update:** The document is written to the off-chain JSON storage file, incrementing its version number.
4. **Digest Anchoring:** A new deterministic SHA-256 hash is calculated and anchored to the ledger.
5. **On-Chain Sealing:** A `WRITE` event is mined into the blockchain ledger.

### 3.4 Revoking Access (FR-4.3)
1. **Trigger:** Patient revokes previously granted permission with one click.
2. **Smart Contract Update:** Consent status transitions immediately to `revoked`.
3. **On-Chain Sealing:** A `REVOKE` audit block is appended to the ledger.
4. **Immediate Effect:** Any subsequent read/write attempt by that provider is blocked and logged as an unauthorized attempt.

### 3.5 Compliance Audit Trail & Zero-Byte Tamper Detection (FR-4.4)
- **Chronological Master Audit Log:** Compliance officers inspect all historical events (`GRANT`, `REVOKE`, `READ`, `WRITE`, `UNAUTHORIZED_ATTEMPT`, `VERIFY_INTEGRITY`) in reverse chronological order, with multi-attribute filtering.
- **Chain Verification:** Validates every block header hash, previous block pointers, and Merkle root calculations back to the Genesis block.
- **Off-Chain Tamper Detection:** Computes live SHA-256 hashes of off-chain files against on-chain anchored digests. If an attacker or insider modifies a single byte in off-chain storage without going through the smart contract, the auditor interface instantly detects zero-byte tampering (`TAMPER_DETECTED`).

---

## 4. REST API Reference

| Endpoint | Method | Parameters / Body | Description |
|---|---|---|---|
| `/api/status` | `GET` | — | System telemetry, block height, chain validity, active consent count |
| `/api/identities` | `GET` | — | Directory of Patients, Doctors, Clinics, Labs, Pharmacies, Auditor |
| `/api/consents` | `GET` | `patient_id`, `provider_id` | Queries active and historical consent states with expiration countdown |
| `/api/consent/grant` | `POST` | `patient_id`, `provider_id`, `scope`, `duration_seconds`, `purpose` | Grants consent and mints `GRANT` block on ledger |
| `/api/consent/revoke` | `POST` | `patient_id`, `provider_id`, `scope` | Revokes consent and mints `REVOKE` block on ledger |
| `/api/records` | `GET` | `patient_id`, `actor_id`, `category` | Lists records; enforces smart contract access check |
| `/api/record` | `GET` | `record_id`, `actor_id`, `emergency`, `override_reason` | Reads single record; logs `READ` or `UNAUTHORIZED_ATTEMPT` |
| `/api/records/write` | `POST` | `actor_id`, `patient_id`, `category`, `title`, `clinical_data` | Writes off-chain record & anchors hash via `WRITE` block |
| `/api/records/verify-integrity` | `POST` | `actor_id`, `record_id` | Compares live off-chain hash with on-chain digest |
| `/api/records/simulate-tamper` | `POST` | `record_id`, `tampered_field`, `fake_value` | Modifies off-chain file directly to demonstrate tamper detection |
| `/api/records/restore` | `POST` | `record_id` | Restores pristine file from clean snapshot |
| `/api/audit-trail` | `GET` | `patient_id`, `actor_id`, `event_type` | Returns chronological blockchain audit logs |
| `/api/blockchain/blocks` | `GET` | — | Returns all blocks with headers, Merkle roots, and hashes |
| `/api/blockchain/verify` | `GET` | — | Full cryptographic validation of the ledger |
| `/api/reset` | `POST` | — | Resets system to clean seeded baseline |

---

## 5. Verification & Testing

To run the automated 10-test test suite:
```bash
python3 run_healthcare.py --test
# Or:
python3 -m unittest test_healthcare.py
```

### Test Coverage Breakdown:
1. `test_01_identities_seeded`: Validates Patient, Doctor, Lab, and Auditor role initialization.
2. `test_02_grant_access_workflow`: Validates FR 4.1 grant transition and `GRANT` block minting.
3. `test_03_authorized_read_workflow`: Validates FR 4.2 authorized read, SHA-256 verification, and `READ` block.
4. `test_04_unauthorized_read_workflow`: Validates FR 4.2 smart contract rejection and on-chain `UNAUTHORIZED_ATTEMPT` logging.
5. `test_05_scoped_access_enforcement`: Validates granular scope boundaries (`LAB_REPORTS` cannot read `EHR_GENERAL`).
6. `test_06_revoke_access_workflow`: Validates FR 4.3 permission revocation and immediate cutoff.
7. `test_07_expiration_enforcement`: Validates time-bounded expiration and automated access rejection.
8. `test_08_offchain_integrity_and_tamper_detection`: Validates zero-byte off-chain tamper detection and restoration.
9. `test_09_blockchain_chain_and_merkle_verification`: Validates complete mathematical integrity of the blockchain.
10. `test_10_break_glass_emergency_override`: Validates emergency glass-break override with high-priority audit alerts.

---

## 6. Launching the Application

Start the web application and REST API server:
```bash
python3 run_healthcare.py
```
Open **[https://medichain-consent.netlify.app](https://medichain-consent.netlify.app)** in any modern web browser to access:
- **Patient Portal:** Grant permissions, set durations, revoke access, and review personal access trails.
- **Doctor / Provider Portal:** Request access, inspect clinical records, and submit clinical updates.
- **Auditor Console:** Inspect master audit logs, explore blocks, verify ledger integrity, and test off-chain tamper detection.
