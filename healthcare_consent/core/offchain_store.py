"""
Off-Chain Medical Data Store.
Stores sensitive patient Electronic Health Records (EHR), lab results,
and prescriptions outside the blockchain ledger in compliance with
HIPAA / GDPR regulations. Provides deterministic SHA-256 integrity checks
and tamper detection.
"""

import json
import os
import time
import copy
from typing import Dict, Any, List, Optional
from healthcare_consent.core.models import MedicalRecord, Scope


class OffChainMedicalStore:
    """
    Manages off-chain clinical documents.
    Decoupled from on-chain audit log; records are referenced by record_id and verified by hash.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            storage_dir = os.path.join(base_dir, "storage", "records")
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self._in_memory_records: Dict[str, MedicalRecord] = {}
        self._clean_backups: Dict[str, Dict[str, Any]] = {}

    def _file_path(self, record_id: str) -> str:
        safe_id = "".join(c for c in record_id if c.isalnum() or c in ("-", "_"))
        return os.path.join(self.storage_dir, f"{safe_id}.json")

    def save_record(self, record: MedicalRecord) -> str:
        """
        Saves medical record to off-chain file store.
        Updates and returns the deterministic SHA-256 hash.
        """
        record.update_hash()
        self._in_memory_records[record.record_id] = record

        # Save clean backup for tamper-testing reset
        self._clean_backups[record.record_id] = copy.deepcopy(record.to_dict())

        file_path = self._file_path(record.record_id)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)

        return record.sha256_hash

    def get_record(self, record_id: str) -> Optional[MedicalRecord]:
        """Loads record from off-chain file store."""
        file_path = self._file_path(record_id)
        if not os.path.exists(file_path):
            return self._in_memory_records.get(record_id)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            rec = MedicalRecord(
                record_id=data["record_id"],
                patient_id=data["patient_id"],
                category=Scope(data["category"]),
                title=data["title"],
                clinical_data=data["clinical_data"],
                created_at=data["created_at"],
                updated_at=data["updated_at"],
                version=data.get("version", 1),
                sha256_hash=data.get("sha256_hash")
            )
            self._in_memory_records[record_id] = rec
            return rec
        except Exception:
            return self._in_memory_records.get(record_id)

    def list_records_for_patient(
        self,
        patient_id: str,
        category: Optional[Scope] = None
    ) -> List[MedicalRecord]:
        """Returns all off-chain records for a given patient matching scope/category."""
        records = []
        for file_name in os.listdir(self.storage_dir):
            if not file_name.endswith(".json"):
                continue
            rec_id = file_name[:-5]
            rec = self.get_record(rec_id)
            if rec and rec.patient_id == patient_id:
                if category is None or category == Scope.ALL or rec.category == category:
                    records.append(rec)
        return sorted(records, key=lambda r: r.created_at)

    def update_record(
        self,
        record_id: str,
        clinical_data_updates: Dict[str, Any],
        actor_id: str,
        new_title: Optional[str] = None
    ) -> MedicalRecord:
        """
        Updates clinical data in off-chain store, increments version,
        and regenerates SHA-256 hash.
        """
        rec = self.get_record(record_id)
        if not rec:
            raise ValueError(f"Record {record_id} does not exist in off-chain store.")

        rec.clinical_data.update(clinical_data_updates)
        if new_title:
            rec.title = new_title
        rec.updated_at = time.time()
        rec.version += 1
        rec.update_hash()

        self.save_record(rec)
        return rec

    def verify_integrity(self, record_id: str, expected_hash: str) -> Dict[str, Any]:
        """
        Recalculates SHA-256 hash from live off-chain file content
        and compares it against expected on-chain hash.
        """
        rec = self.get_record(record_id)
        if not rec:
            return {
                "record_id": record_id,
                "status": "NOT_FOUND",
                "is_intact": False,
                "message": "Record not found in off-chain storage."
            }

        calculated_hash = rec.calculate_hash()
        is_intact = (calculated_hash == expected_hash)

        return {
            "record_id": record_id,
            "patient_id": rec.patient_id,
            "category": rec.category.value,
            "status": "VERIFIED_INTACT" if is_intact else "TAMPER_DETECTED",
            "is_intact": is_intact,
            "live_file_hash": calculated_hash,
            "ledger_anchored_hash": expected_hash,
            "version": rec.version,
            "checked_at": time.time()
        }

    def simulate_tamper(
        self,
        record_id: str,
        tampered_field: str = "diagnosis",
        fraudulent_value: str = "TAMPERED_UNAUTHORIZED_ALTERATION"
    ) -> Dict[str, Any]:
        """
        Intentionally modifies off-chain JSON storage file WITHOUT ledger knowledge,
        to simulate a malicious insider attack or unauthorized silent modification.
        """
        rec = self.get_record(record_id)
        if not rec:
            raise ValueError(f"Record {record_id} not found.")

        original_hash = rec.calculate_hash()

        # Modify clinical data directly in file
        file_path = self._file_path(record_id)
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        data["clinical_data"][tampered_field] = fraudulent_value
        # Note: Do not update on-chain hash or data["sha256_hash"] legitimately!

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # Force re-read
        self.get_record(record_id)

        return {
            "record_id": record_id,
            "tampered_field": tampered_field,
            "injected_value": fraudulent_value,
            "original_hash": original_hash,
            "message": "Off-chain record modified directly. Live hash no longer matches ledger anchored hash!"
        }

    def restore_record(self, record_id: str) -> bool:
        """Restores record to clean pristine state from backup."""
        if record_id in self._clean_backups:
            clean_data = self._clean_backups[record_id]
            file_path = self._file_path(record_id)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(clean_data, f, indent=2)
            self.get_record(record_id)
            return True
        return False
