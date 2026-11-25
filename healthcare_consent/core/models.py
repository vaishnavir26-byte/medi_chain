"""
Data models and enumerations for Healthcare Consent & Audit Log.
Defines identities, roles, consent states, audit events, and medical records.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, List
import time
import hashlib
import json


class Role(str, Enum):
    PATIENT = "patient"
    DOCTOR = "doctor"
    CLINIC = "clinic"
    LAB = "lab"
    PHARMACY = "pharmacy"
    AUDITOR = "auditor"


class ConsentStatus(str, Enum):
    GRANTED = "granted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Scope(str, Enum):
    ALL = "ALL"
    EHR_GENERAL = "EHR_GENERAL"
    LAB_REPORTS = "LAB_REPORTS"
    PRESCRIPTIONS = "PRESCRIPTIONS"
    IMAGING = "IMAGING"


class EventType(str, Enum):
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    READ = "READ"
    WRITE = "WRITE"
    VERIFY_INTEGRITY = "VERIFY_INTEGRITY"
    UNAUTHORIZED_ATTEMPT = "UNAUTHORIZED_ATTEMPT"


@dataclass
class Identity:
    id: str
    name: str
    role: Role
    organization: str
    email: str
    avatar_color: str = "#2563eb"
    specialty: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["role"] = self.role.value
        return d


@dataclass
class ConsentRecord:
    patient_id: str
    provider_id: str
    scope: Scope
    status: ConsentStatus
    granted_at: float
    expires_at: Optional[float] = None
    revoked_at: Optional[float] = None
    tx_hash: Optional[str] = None
    purpose: str = "Medical diagnosis and care delivery"

    def is_active(self, current_time: Optional[float] = None) -> bool:
        if current_time is None:
            current_time = time.time()
        if self.status != ConsentStatus.GRANTED:
            return False
        if self.expires_at is not None and current_time > self.expires_at:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["scope"] = self.scope.value
        d["status"] = self.status.value
        d["is_active"] = self.is_active()
        return d


@dataclass
class AuditEvent:
    event_id: str
    event_type: EventType
    actor_id: str
    patient_id: str
    record_id: Optional[str]
    record_hash: Optional[str]
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = "SUCCESS"  # SUCCESS or REJECTED / ALERT
    tx_hash: Optional[str] = None
    block_index: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


@dataclass
class MedicalRecord:
    record_id: str
    patient_id: str
    category: Scope
    title: str
    clinical_data: Dict[str, Any]
    created_at: float
    updated_at: float
    version: int = 1
    sha256_hash: Optional[str] = None

    def calculate_hash(self) -> str:
        """Calculates deterministic SHA-256 hash of record payload."""
        payload = {
            "record_id": self.record_id,
            "patient_id": self.patient_id,
            "category": self.category.value if isinstance(self.category, Scope) else self.category,
            "title": self.title,
            "clinical_data": self.clinical_data,
            "version": self.version
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    def update_hash(self):
        self.sha256_hash = self.calculate_hash()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value if isinstance(self.category, Scope) else self.category
        if not self.sha256_hash:
            d["sha256_hash"] = self.calculate_hash()
        return d
