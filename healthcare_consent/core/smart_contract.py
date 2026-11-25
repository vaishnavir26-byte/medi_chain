"""
Smart Contract & Ledger Logic Layer for Healthcare Consent & Audit Logging.
Enforces role-based permissions, patient consent states, granular record scopes,
and expiration rules. Records immutable audit events on the blockchain ledger
for compliance (HIPAA / GDPR).
"""

import time
import uuid
from typing import Dict, Any, List, Optional, Tuple

from healthcare_consent.core.models import (
    Role,
    ConsentStatus,
    Scope,
    EventType,
    ConsentRecord,
    AuditEvent,
    MedicalRecord
)
from healthcare_consent.core.blockchain import BlockchainLedger
from healthcare_consent.core.offchain_store import OffChainMedicalStore


class ConsentSmartContractEngine:
    """
    Executes smart contract business logic for healthcare consent:
    - Grant / Revoke consent
    - Verify authorization before off-chain read/write
    - Record tamper-evident audit logs on-chain
    - Manage record integrity anchoring
    """

    def __init__(self, ledger: BlockchainLedger, storage: OffChainMedicalStore):
        self.ledger = ledger
        self.storage = storage
        # In-memory fast state index: (patient_id, provider_id, scope_value) -> ConsentRecord
        self.consent_registry: Dict[Tuple[str, str, str], ConsentRecord] = {}
        # On-chain anchored record hashes: record_id -> latest_hash
        self.record_anchors: Dict[str, str] = {}

    def _state_key(self, patient_id: str, provider_id: str, scope: Scope) -> Tuple[str, str, str]:
        return (patient_id, provider_id, scope.value if isinstance(scope, Scope) else str(scope))

    def grant_consent(
        self,
        patient_id: str,
        provider_id: str,
        scope: Scope = Scope.ALL,
        duration_seconds: Optional[int] = None,
        purpose: str = "Medical diagnosis and care delivery"
    ) -> Dict[str, Any]:
        """
        Workflow 4.1: Patient grants consent to a healthcare provider.
        Updates consent state and records GRANT event on-chain.
        """
        now = time.time()
        expires_at = (now + duration_seconds) if duration_seconds else None

        consent = ConsentRecord(
            patient_id=patient_id,
            provider_id=provider_id,
            scope=scope if isinstance(scope, Scope) else Scope(scope),
            status=ConsentStatus.GRANTED,
            granted_at=now,
            expires_at=expires_at,
            revoked_at=None,
            purpose=purpose
        )

        key = self._state_key(patient_id, provider_id, consent.scope)
        self.consent_registry[key] = consent

        # Create audit event
        event_id = f"EVT-GRANT-{uuid.uuid4().hex[:8].upper()}"
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=EventType.GRANT,
            actor_id=patient_id,
            patient_id=patient_id,
            record_id=None,
            record_hash=None,
            timestamp=now,
            details={
                "provider_id": provider_id,
                "scope": consent.scope.value,
                "duration_seconds": duration_seconds,
                "expires_at": expires_at,
                "purpose": purpose,
                "action": "Patient granted data access permission"
            },
            status="SUCCESS"
        )

        receipt = self.ledger.record_audit_event(audit_event)
        consent.tx_hash = receipt["tx_hash"]

        return {
            "success": True,
            "consent": consent.to_dict(),
            "receipt": receipt,
            "message": f"Consent GRANTED to provider {provider_id} for scope {consent.scope.value}."
        }

    def revoke_consent(
        self,
        patient_id: str,
        provider_id: str,
        scope: Scope = Scope.ALL
    ) -> Dict[str, Any]:
        """
        Workflow 4.3: Patient revokes previously granted permission.
        Updates consent state to revoked and records REVOKE event on-chain.
        """
        scope_enum = scope if isinstance(scope, Scope) else Scope(scope)
        key = self._state_key(patient_id, provider_id, scope_enum)

        consent = self.consent_registry.get(key)
        now = time.time()

        if not consent:
            # Create a revoked record directly if none existed
            consent = ConsentRecord(
                patient_id=patient_id,
                provider_id=provider_id,
                scope=scope_enum,
                status=ConsentStatus.REVOKED,
                granted_at=now,
                revoked_at=now
            )
        else:
            consent.status = ConsentStatus.REVOKED
            consent.revoked_at = now

        self.consent_registry[key] = consent

        # Create audit event
        event_id = f"EVT-REVOKE-{uuid.uuid4().hex[:8].upper()}"
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=EventType.REVOKE,
            actor_id=patient_id,
            patient_id=patient_id,
            record_id=None,
            record_hash=None,
            timestamp=now,
            details={
                "provider_id": provider_id,
                "scope": scope_enum.value,
                "action": "Patient revoked data access permission"
            },
            status="SUCCESS"
        )

        receipt = self.ledger.record_audit_event(audit_event)
        consent.tx_hash = receipt["tx_hash"]

        return {
            "success": True,
            "consent": consent.to_dict(),
            "receipt": receipt,
            "message": f"Consent REVOKED for provider {provider_id} on scope {scope_enum.value}."
        }

    def check_consent(
        self,
        patient_id: str,
        provider_id: str,
        record_category: Scope
    ) -> Tuple[bool, str, Optional[ConsentRecord]]:
        """
        Smart contract evaluation rule:
        Checks whether provider has active, non-expired consent
        either for Scope.ALL or the specific category.
        """
        # Patients always have access to their own records
        if patient_id == provider_id:
            return True, "Patient self-access granted", None

        now = time.time()

        # Check ALL scope first
        all_key = self._state_key(patient_id, provider_id, Scope.ALL)
        if all_key in self.consent_registry:
            c = self.consent_registry[all_key]
            if c.is_active(now):
                return True, "Active consent under Scope.ALL", c
            elif c.status == ConsentStatus.REVOKED:
                return False, "Access revoked by patient under Scope.ALL", c
            elif c.expires_at and now > c.expires_at:
                return False, f"Consent expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(c.expires_at))}", c

        # Check specific scope
        cat_enum = record_category if isinstance(record_category, Scope) else Scope(record_category)
        spec_key = self._state_key(patient_id, provider_id, cat_enum)
        if spec_key in self.consent_registry:
            c = self.consent_registry[spec_key]
            if c.is_active(now):
                return True, f"Active consent under specific Scope: {cat_enum.value}", c
            elif c.status == ConsentStatus.REVOKED:
                return False, f"Access revoked by patient for {cat_enum.value}", c
            elif c.expires_at and now > c.expires_at:
                return False, f"Consent expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(c.expires_at))}", c

        return False, f"No active consent found for provider {provider_id} on {cat_enum.value}", None

    def read_record(
        self,
        actor_id: str,
        patient_id: str,
        record_id: str,
        emergency_override: bool = False,
        override_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Workflow 4.2 (Read):
        1. Verifies active consent under smart contract rules.
        2. If authorized, accesses off-chain record & verifies cryptographic hash.
        3. Logs READ event on-chain.
        4. If unauthorized, denies access and logs UNAUTHORIZED_ATTEMPT on-chain!
        """
        now = time.time()
        record = self.storage.get_record(record_id)
        if not record:
            return {"success": False, "error": f"Record {record_id} not found."}

        # Check consent
        authorized, reason, consent = self.check_consent(patient_id, actor_id, record.category)

        # Handle Break-Glass Emergency Override
        if not authorized and emergency_override:
            authorized = True
            reason = f"BREAK-GLASS EMERGENCY OVERRIDE: {override_reason or 'Emergency Room Admission'}"

        if not authorized:
            # Log UNAUTHORIZED_ATTEMPT on-chain for compliance tracking
            event_id = f"EVT-UNAUTH-{uuid.uuid4().hex[:8].upper()}"
            audit_event = AuditEvent(
                event_id=event_id,
                event_type=EventType.UNAUTHORIZED_ATTEMPT,
                actor_id=actor_id,
                patient_id=patient_id,
                record_id=record_id,
                record_hash=self.record_anchors.get(record_id),
                timestamp=now,
                details={
                    "denial_reason": reason,
                    "attempted_category": record.category.value,
                    "record_title": record.title
                },
                status="ALERT_REJECTED"
            )
            receipt = self.ledger.record_audit_event(audit_event)

            return {
                "success": False,
                "authorized": False,
                "reason": reason,
                "audit_receipt": receipt,
                "message": f"ACCESS DENIED: Smart contract prevented unauthorized read. Event logged on-chain."
            }

        # Authorized read: verify off-chain integrity against anchored hash
        anchored_hash = self.record_anchors.get(record_id, record.calculate_hash())
        integrity_check = self.storage.verify_integrity(record_id, anchored_hash)

        # Log READ event on-chain
        event_id = f"EVT-READ-{uuid.uuid4().hex[:8].upper()}"
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=EventType.READ,
            actor_id=actor_id,
            patient_id=patient_id,
            record_id=record_id,
            record_hash=record.sha256_hash or anchored_hash,
            timestamp=now,
            details={
                "authorization_rule": reason,
                "record_category": record.category.value,
                "record_title": record.title,
                "integrity_intact": integrity_check["is_intact"],
                "emergency_override": emergency_override
            },
            status="SUCCESS" if integrity_check["is_intact"] else "ALERT_HASH_MISMATCH"
        )
        receipt = self.ledger.record_audit_event(audit_event)

        return {
            "success": True,
            "authorized": True,
            "record": record.to_dict(),
            "integrity": integrity_check,
            "audit_receipt": receipt,
            "message": "Record retrieved from off-chain store. Access logged on blockchain."
        }

    def write_record(
        self,
        actor_id: str,
        patient_id: str,
        category: Scope,
        title: str,
        clinical_data: Dict[str, Any],
        record_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Workflow 4.2 (Write):
        1. Verifies active consent under smart contract rules.
        2. Writes/updates record in off-chain store.
        3. Computes new SHA-256 hash.
        4. Anchors hash to on-chain state and logs WRITE event in blockchain.
        """
        now = time.time()
        cat_enum = category if isinstance(category, Scope) else Scope(category)

        # Check consent
        authorized, reason, consent = self.check_consent(patient_id, actor_id, cat_enum)
        if not authorized:
            # Log UNAUTHORIZED_ATTEMPT
            event_id = f"EVT-UNAUTH-WRITE-{uuid.uuid4().hex[:8].upper()}"
            audit_event = AuditEvent(
                event_id=event_id,
                event_type=EventType.UNAUTHORIZED_ATTEMPT,
                actor_id=actor_id,
                patient_id=patient_id,
                record_id=record_id,
                record_hash=None,
                timestamp=now,
                details={
                    "denial_reason": reason,
                    "action": "Attempted unauthorized record creation/update",
                    "category": cat_enum.value
                },
                status="ALERT_REJECTED"
            )
            receipt = self.ledger.record_audit_event(audit_event)
            return {
                "success": False,
                "authorized": False,
                "reason": reason,
                "audit_receipt": receipt,
                "message": "WRITE REJECTED: Smart contract blocked unauthorized record creation."
            }

        # Authorized write: create or update off-chain record
        if record_id and self.storage.get_record(record_id):
            updated_rec = self.storage.update_record(
                record_id=record_id,
                clinical_data_updates=clinical_data,
                actor_id=actor_id,
                new_title=title
            )
            record = updated_rec
            is_new = False
        else:
            rec_id = record_id or f"REC-{cat_enum.value[:3]}-{uuid.uuid4().hex[:6].upper()}"
            record = MedicalRecord(
                record_id=rec_id,
                patient_id=patient_id,
                category=cat_enum,
                title=title,
                clinical_data=clinical_data,
                created_at=now,
                updated_at=now,
                version=1
            )
            self.storage.save_record(record)
            is_new = True

        new_hash = record.calculate_hash()
        self.record_anchors[record.record_id] = new_hash

        # Log WRITE event on-chain
        event_id = f"EVT-WRITE-{uuid.uuid4().hex[:8].upper()}"
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=EventType.WRITE,
            actor_id=actor_id,
            patient_id=patient_id,
            record_id=record.record_id,
            record_hash=new_hash,
            timestamp=now,
            details={
                "action": "RECORD_CREATED" if is_new else "RECORD_UPDATED",
                "record_category": cat_enum.value,
                "record_title": title,
                "version": record.version
            },
            status="SUCCESS"
        )
        receipt = self.ledger.record_audit_event(audit_event)

        return {
            "success": True,
            "record": record.to_dict(),
            "sha256_hash": new_hash,
            "audit_receipt": receipt,
            "message": f"Medical record {'created' if is_new else 'updated'} off-chain. Hash anchored on blockchain."
        }

    def verify_record_integrity(self, actor_id: str, record_id: str) -> Dict[str, Any]:
        """
        Compliance / Auditor tool:
        Checks live off-chain file hash against on-chain anchored hash.
        Logs VERIFY_INTEGRITY event on-chain.
        """
        now = time.time()
        anchored_hash = self.record_anchors.get(record_id)
        rec = self.storage.get_record(record_id)

        if not rec:
            return {"success": False, "error": f"Record {record_id} does not exist."}

        if not anchored_hash:
            anchored_hash = rec.calculate_hash()
            self.record_anchors[record_id] = anchored_hash

        integrity = self.storage.verify_integrity(record_id, anchored_hash)

        # Log verification check on-chain
        event_id = f"EVT-VERIFY-{uuid.uuid4().hex[:8].upper()}"
        audit_event = AuditEvent(
            event_id=event_id,
            event_type=EventType.VERIFY_INTEGRITY,
            actor_id=actor_id,
            patient_id=rec.patient_id,
            record_id=record_id,
            record_hash=integrity["live_file_hash"],
            timestamp=now,
            details={
                "is_intact": integrity["is_intact"],
                "live_hash": integrity["live_file_hash"],
                "anchored_hash": anchored_hash
            },
            status="SUCCESS" if integrity["is_intact"] else "ALERT_INTEGRITY_VIOLATION"
        )
        receipt = self.ledger.record_audit_event(audit_event)

        return {
            "success": True,
            "integrity": integrity,
            "receipt": receipt
        }

    def get_all_consents(
        self,
        patient_id: Optional[str] = None,
        provider_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Returns list of consent records with active status flag."""
        now = time.time()
        results = []
        for consent in self.consent_registry.values():
            if patient_id and consent.patient_id != patient_id:
                continue
            if provider_id and consent.provider_id != provider_id:
                continue

            c_dict = consent.to_dict()
            # Dynamic active check including expiration
            c_dict["is_active"] = consent.is_active(now)
            if consent.expires_at and now > consent.expires_at and consent.status == ConsentStatus.GRANTED:
                c_dict["status"] = "expired"
            results.append(c_dict)

        return sorted(results, key=lambda x: x["granted_at"], reverse=True)
